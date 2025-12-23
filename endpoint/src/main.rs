use log::{error, info, LevelFilter};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::signal;
use trusttunnel::authentication::registry_based::RegistryBasedAuthenticator;
use trusttunnel::authentication::Authenticator;
use trusttunnel::client_config;
use trusttunnel::core::Core;
use trusttunnel::settings::Settings;
use trusttunnel::shutdown::Shutdown;
use trusttunnel::{log_utils, settings};

const VERSION_STRING: &str = env!("CARGO_PKG_VERSION");

const VERSION_PARAM_NAME: &str = "v_e_r_s_i_o_n_do_not_change_this_name_it_will_break";
const LOG_LEVEL_PARAM_NAME: &str = "log_level";
const LOG_FILE_PARAM_NAME: &str = "log_file";
const SETTINGS_PARAM_NAME: &str = "settings";
const TLS_HOSTS_SETTINGS_PARAM_NAME: &str = "tls_hosts_settings";
const CLIENT_CONFIG_PARAM_NAME: &str = "client_config";
const ADDRESS_PARAM_NAME: &str = "address";
const SENTRY_DSN_PARAM_NAME: &str = "sentry_dsn";
const THREADS_NUM_PARAM_NAME: &str = "threads_num";

fn main() {
    let args = clap::Command::new("VPN endpoint")
        .args(&[
            // Built-in version parameter handling is deficient in that it
            // outputs `<program name> <version>` instead of just `<version>`
            // and also uses `-V` instead of `-v` as the shorthand.
            clap::Arg::new(VERSION_PARAM_NAME)
                .short('v')
                .long("version")
                .action(clap::ArgAction::SetTrue)
                .help("Print the version of this software and exit"),
            clap::Arg::new(LOG_LEVEL_PARAM_NAME)
                .short('l')
                .long("loglvl")
                .action(clap::ArgAction::Set)
                .value_parser(["info", "debug", "trace"])
                .default_value("info")
                .help("Logging level"),
            clap::Arg::new(LOG_FILE_PARAM_NAME)
                .long("logfile")
                .action(clap::ArgAction::Set)
                .help("File path for storing logs. If not specified, the logs are printed to stdout"),
            clap::Arg::new(SENTRY_DSN_PARAM_NAME)
                .long(SENTRY_DSN_PARAM_NAME)
                .action(clap::ArgAction::Set)
                .help("Sentry DSN (see https://docs.sentry.io/product/sentry-basics/dsn-explainer/ for details)"),
            clap::Arg::new(THREADS_NUM_PARAM_NAME)
                .long("jobs")
                .action(clap::ArgAction::Set)
                .value_parser(clap::value_parser!(usize))
                .help("The number of worker threads. If not specified, set to the number of CPUs on the machine."),
            clap::Arg::new(SETTINGS_PARAM_NAME)
                .action(clap::ArgAction::Set)
                .required_unless_present(VERSION_PARAM_NAME)
                .help("Path to a settings file"),
            clap::Arg::new(TLS_HOSTS_SETTINGS_PARAM_NAME)
                .action(clap::ArgAction::Set)
                .required_unless_present(VERSION_PARAM_NAME)
                .help("Path to a file containing TLS hosts settings. Sending SIGHUP to the process causes reloading the settings."),
            clap::Arg::new(CLIENT_CONFIG_PARAM_NAME)
                .action(clap::ArgAction::Set)
                .requires(ADDRESS_PARAM_NAME)
                .short('c')
                .long("client_config")
                .value_names(["client_name"])
                .help("Print the endpoint config for specified client and exit."),
            clap::Arg::new(ADDRESS_PARAM_NAME)
                .action(clap::ArgAction::Append)
                .requires(CLIENT_CONFIG_PARAM_NAME)
                .short('a')
                .long("address")
                .help("Endpoint address to be added to client's config.")
        ])
        .disable_version_flag(true)
        .get_matches();

    if args.contains_id(VERSION_PARAM_NAME)
        && Some(true) == args.get_one::<bool>(VERSION_PARAM_NAME).copied()
    {
        println!("{}", VERSION_STRING);
        return;
    }

    #[cfg(feature = "tracing")]
    console_subscriber::init();

    let _guard = args.get_one::<String>(SENTRY_DSN_PARAM_NAME).map(|x| {
        sentry::init((
            x.clone(),
            sentry::ClientOptions {
                release: sentry::release_name!(),
                ..Default::default()
            },
        ))
    });

    let _guard = log_utils::LogFlushGuard;
    log::set_logger(match args.get_one::<String>(LOG_FILE_PARAM_NAME) {
        None => log_utils::make_stdout_logger(),
        Some(file) => log_utils::make_file_logger(file).expect("Couldn't open the logging file"),
    })
    .expect("Couldn't set logger");

    log::set_max_level(
        match args
            .get_one::<String>(LOG_LEVEL_PARAM_NAME)
            .map(String::as_str)
        {
            None => LevelFilter::Info,
            Some("info") => LevelFilter::Info,
            Some("debug") => LevelFilter::Debug,
            Some("trace") => LevelFilter::Trace,
            Some(x) => panic!("Unexpected log level: {}", x),
        },
    );

    let settings_path = args.get_one::<String>(SETTINGS_PARAM_NAME).unwrap();
    let settings: Settings = toml::from_str(
        &std::fs::read_to_string(settings_path).expect("Couldn't read the settings file"),
    )
    .expect("Couldn't parse the settings file");

    let tls_hosts_settings_path = args
        .get_one::<String>(TLS_HOSTS_SETTINGS_PARAM_NAME)
        .unwrap();
    let tls_hosts_settings: settings::TlsHostsSettings = toml::from_str(
        &std::fs::read_to_string(tls_hosts_settings_path)
            .expect("Couldn't read the TLS hosts settings file"),
    )
    .expect("Couldn't parse the TLS hosts settings file");

    if args.contains_id(CLIENT_CONFIG_PARAM_NAME) {
        let username = args.get_one::<String>(CLIENT_CONFIG_PARAM_NAME).unwrap();
        let addresses: Vec<SocketAddr> = args
            .get_many::<String>(ADDRESS_PARAM_NAME)
            .expect("At least one address should be specified")
            .map(|x| {
                SocketAddr::from_str(x)
                    .or_else(|_| {
                        SocketAddr::from_str(&format!("{}:{}", x, settings.get_listen_address().port()))
                    })
                    .unwrap_or_else(|_| {
                        panic!("Failed to parse address. Expected `ip` or `ip:port` format, found: `{}`", x);
                    }) 
            })
            .collect();

        let client_config = client_config::build(
            &username,
            addresses,
            settings.get_clients(),
            &tls_hosts_settings,
        );
        println!("{}", client_config.compose_toml());
        return;
    }

    let rt = {
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.enable_io();
        builder.enable_time();

        if let Some(n) = args.get_one::<usize>(THREADS_NUM_PARAM_NAME) {
            builder.worker_threads(*n);
        }

        builder.build().expect("Failed to set up runtime")
    };

    let shutdown = Shutdown::new();
    let authenticator: Option<Arc<dyn Authenticator>> = if !settings.get_clients().is_empty() {
        Some(Arc::new(RegistryBasedAuthenticator::new(
            settings.get_clients(),
        )))
    } else {
        None
    };
    let core = Arc::new(
        Core::new(
            settings,
            authenticator,
            tls_hosts_settings,
            shutdown.clone(),
        )
        .expect("Couldn't create core instance"),
    );

    let listen_task = {
        let core = core.clone();
        async move { core.listen().await }
    };

    let reload_tls_hosts_task = {
        let tls_hosts_settings_path = tls_hosts_settings_path.clone();
        async move {
            let mut sighup_listener = signal::unix::signal(signal::unix::SignalKind::hangup())
                .expect("Couldn't start SIGHUP listener");

            loop {
                sighup_listener.recv().await;
                info!("Reloading TLS hosts settings");

                let tls_hosts_settings: settings::TlsHostsSettings = toml::from_str(
                    &std::fs::read_to_string(&tls_hosts_settings_path)
                        .expect("Couldn't read the TLS hosts settings file"),
                )
                .expect("Couldn't parse the TLS hosts settings file");

                core.reload_tls_hosts_settings(tls_hosts_settings)
                    .expect("Couldn't apply new settings");
                info!("TLS hosts settings are successfully reloaded");
            }
        }
    };

    let interrupt_task = async move {
        tokio::signal::ctrl_c().await.unwrap();
        shutdown.lock().unwrap().submit();
        shutdown.lock().unwrap().completion().await
    };

    rt.block_on(async move {
        tokio::select! {
            listen_result = listen_task => listen_result.expect("Error while listening IO events"),
            _ = reload_tls_hosts_task => error!("Error while reloading TLS hosts"),
            _ = interrupt_task => info!("Interrupted by user"),
        }
    });
}
