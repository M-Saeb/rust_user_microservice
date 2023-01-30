
use surrealdb::Datastore;
use surrealdb::Session as SRSession;
use surrealdb::Response;
use surrealdb::Error;

use crate::user::User;
use crate::session::Session as DBSession;
use crate::utils as format_utils;

pub struct Database{
	datastore: Datastore,
	surreal_ns: String,
	surreal_db: String,
	session: SRSession,
}

impl Database {
	pub async fn connect(path: &str, ns: & str, db: & str) -> Result<Database, Error> {
		let dt = Datastore::new(path).await?;
		let session = SRSession::for_kv();
		let db = Database{
			datastore: dt,
			surreal_ns: ns.to_owned(),
			surreal_db: db.to_owned(),
			session: session,
		};
		Ok(db)
	}

	async fn excute(&mut self, query: &str) -> Result<Vec<Response>, Error>{
		let init_query = format!("USE NS {} DB {}; ", self.surreal_ns, self.surreal_db );
		let full_query = init_query + query;
	    let response = self.datastore.execute(
			full_query.as_str(),
			&self.session,
			None,
			false
		).await?;
		Ok(response)

	}

	async fn check_if_username_unique(&mut self, username: &str) -> Result<bool, Error>{
		let query = User::generate_get_user_by_username_query(username);
		let raw_response = self.excute(&query).await?;
		let formatted_reponse = format_utils::vec_response_to_query_response(raw_response);
		match formatted_reponse {
			Ok(res) => return Ok(false),
			Err(res) => return Ok(true)
		}
	}

	async fn check_if_email_unique(&mut self, email: &str) -> Result<bool, Error>{
		let query = User::generate_get_user_by_email_query(email);
		let raw_response = self.excute(&query).await?;
		let formatted_reponse = format_utils::vec_response_to_query_response(raw_response);
		match formatted_reponse {
			Ok(res) => return Ok(false),
			Err(res) => return Ok(true)
		}
	}

	pub async fn create_user(&mut self, user: User) -> Result<User, Error>{
		let username_is_unique = self.check_if_username_unique(&user.username).await?;
		if !username_is_unique{
			return Err( Error::Tx("User with this username already exist".into()) )
		}
		let email_is_unique = self.check_if_email_unique(&user.email).await?;
		if !email_is_unique{
			return Err( Error::Tx("User with this email already exist".into()) )
		}
		let create_query = user.generate_create_query();
		let raw_response = self.excute(create_query.as_ref()).await?;
		let formatted_reponse = format_utils::vec_response_to_query_response(raw_response);
		match formatted_reponse {
			Ok(res) => {
				let user = User::from_object_response(res);
				Ok(user)						
			},
			Err(res) => panic!("Couldn't fomat user response")
		}
	}

	pub async fn create_session(&mut self, session: DBSession) -> Result<DBSession, Error>{
		let query = session.generate_create_query();
		let raw_response = self.excute(query.as_ref()).await?;
		let formatted_reponse = format_utils::vec_response_to_query_response(raw_response);
		match formatted_reponse {
			Ok(res) => {
				let session = DBSession::from_object_response(res);
				Ok(session)
			},
			Err(res) => panic!("Couldn't fomat session response")
		}
	}

	pub async fn get_session_by_key(&mut self, session_key: &str) -> Result<DBSession, Error >{
		let query = DBSession::generate_select_by_key_query(session_key);
		let raw_response = self.excute(query.as_ref()).await?;
		let formatted_reponse = format_utils::vec_response_to_query_response(raw_response);
		match formatted_reponse {
			Ok(res) => {
				let session = DBSession::from_object_response(res);
				Ok(session)
			},
			Err(res) => Err( Error::Tx("Session was not found".into()) )
		}
	}

	pub async fn delete_session(&mut self, session_key: &str) -> Result<(), Error>{
		let query = DBSession::generate_delete_by_key_query(session_key);
		let raw_response = self.excute(query.as_ref()).await?;
		Ok(())
	}


}


#[cfg(test)]
mod test_db {
    use crate::{Database, User, session::Session as DBSession};
	use surrealdb::Error as Error;
	use pwhash::bcrypt;

	#[tokio::test]
    async fn test_db_conenction() -> Result<(), Error>{
		Database::connect("memory", "test", "test").await?;
		Ok(())
    }

	#[tokio::test]
    async fn test_create_user_1() -> Result<(), Error> {
		let mut db = Database::connect("memory", "test", "test").await?;
		let user = db.create_user(
			User::create_obj("username", "email", "password")
		).await?;
		assert!(user.id.is_some(), "ID was not set for user !!");
		assert_eq!(user.username, "username");
		assert_eq!(user.email, "email");
		let is_valid_password = bcrypt::verify("password", &user.password);
		assert!(
			is_valid_password,
			"Not a valid a password"
		);
		Ok(())
	}

	#[tokio::test]
    async fn test_create_user_2() -> Result<(), Error> {
		let mut db = Database::connect("memory", "test", "test").await?;
		db.excute("
			CREATE user SET
			username = 'username',
			email = 'test@email.com',
			password = 'password',
			created_on = time::now()
		;").await?;

		let user = db.create_user(
			User::create_obj("username", "email", "password")
		).await;

		let err = user.expect_err("an error should've been raised");
		assert_eq!(
			err.to_string(),
			"There was a problem with a datastore transaction: User with this username already exist".to_string()
		);

		Ok(())
	}

	#[tokio::test]
    async fn test_create_user_3() -> Result<(), Error> {
		let mut db = Database::connect("memory", "test", "test").await?;
		db.excute("
			CREATE user SET
			username = 'username',
			email = 'test@email.com',
			password = 'password',
			created_on = time::now()
		;").await?;

		let user = db.create_user(
			User::create_obj("ranadom", "test@email.com", "password")
		).await;

		let err = user.expect_err("an error should've been raised");
		assert_eq!(
			err.to_string(),
			"There was a problem with a datastore transaction: User with this email already exist".to_string()
		);

		Ok(())
	}

	#[tokio::test]
    async fn test_create_session() -> Result<(), Error> {
		let mut db = Database::connect("memory", "test", "test").await?;
		let session = db.create_session(
			DBSession::create_obj("user_id")
		).await?;
		assert_eq!(session.key.len(), 32);
		assert_eq!(session.user, "user_id");
		Ok(())
	}

	#[tokio::test]
    async fn test_get_session_by_key_1() -> Result<(), Error > {
		let mut db = Database::connect("memory", "test", "test").await?;
		db.excute("
			CREATE session SET
			user = 'some_user_id',
			key = '123456789',
			created_on = time::now()
		;").await?;
		let session = db.get_session_by_key("123456789").await?;

		Ok(())
	}

	#[tokio::test]
    async fn test_get_session_by_key_2() -> Result<(), Error > {
		let mut db = Database::connect("memory", "test", "test").await?;
		let session = db.get_session_by_key("123456789").await;
		match session {
			Ok(res) => panic!("That shouldn't have happened"),
			Err(err) => {
				assert_eq!(
					err.to_string(),
					"There was a problem with a datastore transaction: Session was not found".to_string()
				);
			}
		}
		Ok(())
	}

	#[tokio::test]
    async fn test_delete_session_1() -> Result<(), Error > {
		let mut db = Database::connect("memory", "test", "test").await?;
		db.excute("
			CREATE session SET
			user = 'some_user_id',
			key = '123456789',
			created_on = time::now()
		;").await?;
		db.delete_session("123456789").await?;
		Ok(())
	}

	#[tokio::test]
    async fn test_delete_session_2() -> Result<(), Error > {
		let mut db = Database::connect("memory", "test", "test").await?;
		db.delete_session("123456789").await?;
		Ok(())
	}


}
