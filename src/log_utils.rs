use std::fmt::{Display, Formatter};
use dynfmt::Format;


#[macro_export]
macro_rules! log_id {
    ($lvl:ident, $id_chain:expr, $msg:expr) => {
        $lvl!(std::concat!("[{}] ", $msg), $id_chain)
    };
    ($lvl:ident, $id_chain:expr, $fmt:expr, $($arg:tt)*) => {
        $lvl!(std::concat!("[{}] ", $fmt), $id_chain, $($arg)*)
    };
}


pub(crate) const CLIENT_ID_FMT: &str = "CLIENT={}";
pub(crate) const TUNNEL_ID_FMT: &str = "TUN={}";
pub(crate) const CONNECTION_ID_FMT: &str = "CONN={}";



#[derive(Copy, Clone)]
pub struct IdItem<T: Copy + serde::ser::Serialize> {
    fmt: &'static str,
    id: T,
}

#[derive(Clone)]
pub struct IdChain<T: Copy + serde::ser::Serialize> {
    list: Vec<IdItem<T>>,
}

impl<T: Copy + serde::ser::Serialize> IdItem<T> {
    pub fn new(
        fmt: &'static str,
        id: T,
    ) -> Self {
        Self { fmt, id }
    }
}

impl<T: Copy + serde::ser::Serialize> IdChain<T> {
    pub fn extended(&self, new: IdItem<T>) -> Self {
        let mut x = Self::with_capacity(self.list.len() + 1);
        x.list.extend(self.list.iter());
        x.list.push(new);
        x
    }

    fn with_capacity(cap: usize) -> Self {
        Self {
            list: Vec::with_capacity(cap),
        }
    }
}

impl<T: Copy + serde::ser::Serialize> From<IdItem<T>> for IdChain<T> {
    fn from(x: IdItem<T>) -> Self {
        Self {
            list: vec![x],
        }
    }
}

impl<T: Copy + serde::ser::Serialize> Display for IdChain<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = self.list.iter()
            .fold(String::new(), |acc, i| {
                let x = dynfmt::curly::SimpleCurlyFormat
                    .format(i.fmt, &[i.id])
                    .unwrap();

                if !acc.is_empty() {
                    acc + "/" + x.as_ref()
                } else {
                    x.to_string()
                }
            });
        write!(f, "{}", str)
    }
}

#[cfg(test)]
mod tests {
    use crate::log_utils::{IdChain, IdItem};

    #[test]
    fn test() {
        let mut chain = IdChain::from(IdItem::new("hello {}", 42));
        assert_eq!("hello 42", format!("{}", chain));

        chain = chain.extended(IdItem::new("ok {}", 73));
        assert_eq!("hello 42/ok 73", format!("{}", chain));
    }
}
