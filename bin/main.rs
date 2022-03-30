use std::fs::File;
use std::io::BufReader;
use log::{Level, LevelFilter, Metadata, Record};
use vpn_libs_endpoint::core::Core;
use vpn_libs_endpoint::settings::Settings;


const LOG_LEVEL_PARAM_NAME: &str = "log_level";
const CONFIG_PARAM_NAME: &str = "config";


static LOGGER: StdoutLogger = StdoutLogger;


fn main() {
    let args = clap::Command::new("VPN endpoint")
        .args(&[
            clap::Arg::new(LOG_LEVEL_PARAM_NAME)
                .short('l')
                .long("loglvl")
                .takes_value(true)
                .possible_values(["info", "debug", "trace"])
                .default_value("info")
                .help("Logging level"),
            clap::Arg::new(CONFIG_PARAM_NAME)
                .takes_value(true)
                .required(true)
                .help("Path to a configuration file"),
        ])
        .get_matches();

    log::set_logger(&LOGGER).unwrap();

    log::set_max_level(match args.value_of(LOG_LEVEL_PARAM_NAME) {
        None => LevelFilter::Info,
        Some("info") => LevelFilter::Info,
        Some("debug") => LevelFilter::Debug,
        Some("trace") => LevelFilter::Trace,
        Some(x) => panic!("Unexpected log level: {}", x),
    });

    let config_path = args.value_of(CONFIG_PARAM_NAME).unwrap();
    let parsed: Settings = serde_json::from_reader(BufReader::new(
        File::open(config_path).expect("Couldn't open the configuration file")
    )).expect("Failed parsing the configuration file");

    let mut core = Core::new(parsed);
    core.listen().unwrap()
}


struct StdoutLogger;

impl log::Log for StdoutLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Trace
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            println!("{} [{:?}] [{}] [{}] {}",
                     chrono::Local::now().format("%T.%6f"), std::thread::current().id(),
                     record.level(), record.target(), record.args());
        }
    }

    fn flush(&self) {}
}
