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
	pub async fn create_user(&mut self, user: User) -> Result<User, Error>{
		let query = user.generate_create_query();
		let raw_responses = self.excute(query.as_ref()).await?;
		let formatted_reponse = format_utils::vec_response_to_query_response(raw_responses);
		let user = User::from_object_response(formatted_reponse);
		Ok(user)
	}

	pub async fn login(&mut self, username: &str, password: &str) -> Result<DBSession, Error>{
		let fetch_user_query = format!("
			SELECT * FROM user WHERE username = {} AND password = {};
		", username, password);
		let raw_response = self.excute(&fetch_user_query).await?;
		let formatted_response = format_utils::vec_response_to_query_response(raw_response);
		let user = User::from_object_response(formatted_response);
		dbg!(&user);
		let user_id = user.id.expect("ID not found");
		let session = DBSession::create_obj(user_id.as_str());
		dbg!(&session);
		Ok(session)
	}

	pub async fn logout(){} // TODO
	pub async fn get_user_from_session(){} // TODO

}


#[cfg(test)]
mod test_db {
    use crate::{Database, User};
	use surrealdb::Error;
	use pwhash::bcrypt;

	#[tokio::test]
    async fn test_db_conenction() -> Result<(), Error>{
		Database::connect("memory", "test", "test").await?;
		Ok(())
    }

	#[tokio::test]
    async fn test_create_user() -> Result<(), Error> {
		let mut db = Database::connect("memory", "test", "test").await?;
		let response = db.create_user(
			User::create_obj("username", "email", "password")
		).await?;
		// dbg!(&response);
		Ok(())
	}

	#[tokio::test]
    async fn test_login() -> Result<(), Error> {
		let mut db = Database::connect("memory", "test", "test").await?;
		let user = db.create_user(
			User::create_obj("username", "email", "password")
		).await?;

		let session = db.login("username", "password").await?;
		assert_eq!(session.user, user.id.expect("no ID was set"));
		assert_eq!(session.key.len(), 32);

		Ok(())
	}

	#[tokio::test]
    async fn test_user_response_to_user_struct() -> Result<(), Error> {
		let mut db = Database::connect("memory", "test", "test").await?;
		let user = db.create_user(
			User::create_obj("username", "email", "password")
		).await?;

		assert!(user.id.is_some(), "Id is not set !");
		assert_eq!(user.username, "username");
		assert_eq!(user.email, "email");
		let is_valid_password = bcrypt::verify("password", &user.password);
		assert!(
			is_valid_password,
			"Not a valid a password"
		);

		Ok(())
	}

}
