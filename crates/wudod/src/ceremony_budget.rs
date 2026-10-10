//! Shared, non-waiting ceremony and verifier capacity. Leases survive cancellation.
use std::sync::{Arc, Mutex};
use wudo_protocol::v2::{Error, Result};
use wudo_store::UserId;
#[derive(Clone, Default)]
pub struct Budgets {
    ceremonies: Pool,
    crypto: Pool,
}
#[derive(Clone, Default)]
struct Pool(Arc<Mutex<Vec<UserId>>>);
#[derive(Clone)]
pub struct Lease {
    _inner: Arc<Reservation>,
}
struct Reservation {
    pool: Pool,
    user: UserId,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if let Ok(mut users) = self.pool.0.lock()
            && let Some(i) = users.iter().position(|u| *u == self.user)
        {
            users.swap_remove(i);
        }
    }
}
impl Pool {
    fn reserve(&self, user: UserId, total: usize, per_user: usize) -> Result<Lease> {
        let mut users = self.0.lock().map_err(|_| Error::Unavailable)?;
        if users.len() >= total || users.iter().filter(|u| **u == user).count() >= per_user {
            return Err(Error::Busy);
        }
        users.push(user);
        Ok(Lease {
            _inner: Arc::new(Reservation {
                pool: self.clone(),
                user,
            }),
        })
    }
}
impl Budgets {
    pub fn ceremony(&self, user: UserId) -> Result<Lease> {
        self.ceremonies.reserve(user, 32, 2)
    }
    pub fn crypto(&self, user: UserId) -> Result<Lease> {
        self.crypto.reserve(user, 2, 2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn user(n: u8) -> UserId {
        let mut b = [n; 16];
        b[6] = 0x40;
        b[8] = 0x80;
        UserId::from_bytes(b).unwrap()
    }
    #[test]
    fn clones_share_limits_and_cancelled_jobs_keep_capacity_until_drop() {
        let enrollment = Budgets::default();
        let viewing = enrollment.clone();
        let a = enrollment.ceremony(user(1)).unwrap();
        let b = viewing.ceremony(user(1)).unwrap();
        assert!(matches!(viewing.ceremony(user(1)), Err(Error::Busy)));
        let running = a.clone();
        drop(a);
        assert!(enrollment.ceremony(user(1)).is_err());
        drop(running);
        let replacement = enrollment.ceremony(user(1)).unwrap();
        drop((replacement, b));
        let mut leases = vec![];
        for n in 1..=32 {
            leases.push(viewing.ceremony(user(n)).unwrap());
        }
        assert!(enrollment.ceremony(user(33)).is_err());
        drop(leases);
        assert!(enrollment.ceremony(user(33)).is_ok());
        let a = enrollment.crypto(user(1)).unwrap();
        let b = viewing.crypto(user(2)).unwrap();
        assert!(viewing.crypto(user(3)).is_err());
        drop(a);
        assert!(viewing.crypto(user(3)).is_ok());
        drop(b);
    }
}
