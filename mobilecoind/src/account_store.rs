// Copyright (c) 2018-2020 MobileCoin Inc.

//! Database storage for wallet accounts

use crate::error::Error;

use lmdb::{Database, DatabaseFlags, Environment, RwTransaction, Transaction, WriteFlags};
use mc_account_keys::AccountKey;
use mc_common::logger::{log, Logger};
use prost::Message;
use std::sync::Arc;

// LMDB Database Names
pub const ACCOUNT_DB_NAME: &str = "mobilecoind_db:account_store:account_data";
pub const ACTIVE_DB_NAME: &str = "mobilecoind_db:account_store:active";

/// Key used to get the active account
pub const ACTIVE_KEY: &str = "active";

/// The data associated with an Account.
#[derive(Message, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct AccountData {
    /// If owned, the account_key associated with this address
    #[prost(bytes, tag = "1")]
    pub monitor_id: Vec<u8>,

    #[prost(uint64, tag = "2")]
    pub next_subaddress_index: u64,
}

/// Storage for Accounts.
#[derive(Clone)]
pub struct AccountStore {
    /// Environment for LMDB transactions.
    env: Arc<Environment>,

    /// Mapping of address -> Address Data.
    account_data: Database,

    /// The current active account
    active: Database,

    /// Logger.
    logger: Logger,
}

impl AccountStore {
    /// Create a new AccountStore.
    pub fn new(env: Arc<Environment>, logger: Logger) -> Result<Self, Error> {
        let account_data = env.create_db(Some(ACCOUNT_DB_NAME), DatabaseFlags::empty())?;
        let active = env.create_db(Some(ACTIVE_DB_NAME), DatabaseFlags::empty())?;

        // Update active to be set to None
        let mut db_transaction = env.begin_rw_txn()?;
        db_transaction.put(active, &ACTIVE_KEY, &Vec::new(), WriteFlags::empty())?;
        db_transaction.commit()?;

        Ok(Self {
            env,
            account_data,
            active,
            logger,
        })
    }

    /// Insert a new Account into the database.
    pub fn insert<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        account: &AccountKey,
        data: &AccountData,
    ) -> Result<(), Error> {
        let account_db_key = mc_util_serial::encode(account);

        let value_bytes = mc_util_serial::encode(data);
        match db_txn.put(
            self.account_data,
            &account_db_key,
            &value_bytes,
            WriteFlags::NO_OVERWRITE,
        ) {
            Ok(_) => Ok(()),
            Err(lmdb::Error::KeyExist) => Err(Error::AccountExists),
            Err(err) => Err(err.into()),
        }?;

        log::trace!(
            self.logger,
            "Inserting {:?} ({:?}) to account store",
            account,
            data,
        );

        match self.get_active(db_txn)? {
            // FIXME: map_or_else more concise?
            Some(_) => {}
            None => {
                log::trace!(self.logger, "Setting active account {:?}", account);
                self.set_active(db_txn, &account)?
            }
        };

        Ok(())
    }

    /// Returns the Account Data associated with a given account
    pub fn get(
        &self,
        db_txn: &impl Transaction,
        account: &AccountKey,
    ) -> Result<AccountData, Error> {
        let account_db_key = mc_util_serial::encode(account);
        match db_txn.get(self.account_data, &account_db_key) {
            Ok(value_bytes) => Ok(mc_util_serial::decode(value_bytes)?),
            Err(lmdb::Error::NotFound) => Err(Error::AccountNotFound),
            Err(err) => Err(err.into()),
        }
    }

    /// Update the next subaddress for the account
    pub fn update_next_subaddress<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        account: &AccountKey,
    ) -> Result<(), Error> {
        let account_db_key = mc_util_serial::encode(account);

        match db_txn.get(self.account_data, &account_db_key) {
            Ok(value_bytes) => {
                let mut account_data: AccountData = mc_util_serial::decode(value_bytes)?;
                account_data.next_subaddress_index += 1;
                self.delete(db_txn, account)?; // FIXME: allow overwrite
                self.insert(db_txn, account, &account_data)?;
                Ok(())
            }
            Err(lmdb::Error::NotFound) => Err(Error::AccountNotFound),
            Err(err) => Err(err.into()),
        }
    }

    /// Delete the data stored for an account
    pub fn delete<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        account: &AccountKey,
    ) -> Result<(), Error> {
        let account_db_key = mc_util_serial::encode(account);

        db_txn.del(self.account_data, &account_db_key, None)?;

        Ok(())
    }

    pub fn get_active<'env>(
        &self,
        db_txn: &impl Transaction,
    ) -> Result<Option<AccountData>, Error> {
        log::trace!(self.logger, "Now getting active");
        let active = db_txn.get(self.active, &ACTIVE_KEY)?;

        log::trace!(self.logger, "Got active key = {:?}", active);
        if active == Vec::<u8>::new() {
            log::trace!(self.logger, "empty vec so returning None");
            return Ok(None);
        }

        let active_account: AccountKey = mc_util_serial::decode(active)?;
        log::trace!(self.logger, "Got active account = {:?}", active_account);

        Ok(Some(self.get(db_txn, &active_account)?))
    }

    pub fn set_active<'env>(
        &self,
        db_txn: &mut RwTransaction<'env>,
        account: &AccountKey,
    ) -> Result<(), Error> {
        log::trace!(self.logger, "\x1b[1;33mNow in Set active\x1b[0m");

        let account_db_key = mc_util_serial::encode(account);
        log::trace!(self.logger, "Setting active to {:?}", account_db_key);
        // Verify that account is in DB
        match db_txn.get(self.account_data, &account_db_key) {
            Ok(_) => {
                db_txn.put(
                    self.active,
                    &ACTIVE_KEY,
                    &account_db_key,
                    WriteFlags::empty(),
                )?;
                Ok(())
            }
            Err(lmdb::Error::NotFound) => Err(Error::AccountNotFound),
            Err(err) => Err(err.into()),
        }
    }

    // TODO: ListAccounts
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::get_test_monitor_data_and_id;
    use mc_common::logger::{test_with_logger, Logger};
    use rand::{rngs::StdRng, SeedableRng};
    use tempdir::TempDir;

    #[test_with_logger]
    fn test_set_active(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);

        let db_tmp = TempDir::new("account_store_db").expect("Could not make tempdir for test");
        let db_path = db_tmp
            .path()
            .to_str()
            .expect("Could not get path as string");

        let env = Arc::new(
            Environment::new()
                .set_max_dbs(10)
                .set_map_size(10000000)
                .open(db_path.as_ref())
                .unwrap(),
        );
        let account_store = AccountStore::new(env.clone(), logger).unwrap();

        // Test that on initialization, the active account is None
        {
            let db_txn = env.begin_ro_txn().unwrap();
            assert!(account_store.get_active(&db_txn).unwrap().is_none());
        }

        // Test that after inserting to empty, the active account is Some
        {
            let mut db_txn = env.begin_rw_txn().unwrap();
            let (monitor_data, monitor_id) = get_test_monitor_data_and_id(&mut rng);
            let account_data = AccountData {
                monitor_id: monitor_id.to_vec(),
                next_subaddress_index: 0,
            };
            account_store
                .insert(&mut db_txn, &monitor_data.account_key, &account_data)
                .unwrap();
            assert_eq!(
                account_store.get_active(&db_txn).unwrap().unwrap(),
                account_data
            )
        }

        {}
    }
}
