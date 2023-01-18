mod utils;

use surrealdb::Datastore;
use surrealdb::Session;
use surrealdb::Response;
use surrealdb::Error;
use surrealdb::sql::{Value, Object};
use pwhash::bcrypt;
use crate::utils as format_utils;

fn hash_string(raw_password: &str) -> String{
	let hash_string = bcrypt::hash(raw_password).unwrap();
	hash_string
}

#[derive(Debug)]
pub struct User{
	pub username: String,
	pub email: String,
	password: String
}

impl User {
	fn generate_create_query(&self) -> String {
		let query = format!("
			CREATE user SET
			username = '{}',
			email = '{}',
			password = '{}',
			created_on = time::now()
			;", self.username, self.email, self.password);
		query
	}

	pub fn create_obj(username: &str, email: &str, raw_password: &str) -> User {
		let hashed_password = hash_string(raw_password);
		dbg!(&hashed_password);
		let new_user = User {
			username: username.to_owned(),
			email: email.to_owned(),
			password: hashed_password,
		};
		new_user
	}

	pub fn from_object_response(response_object: Object) -> User {
		let username_oject = response_object.get("username").expect("username not found");
		let mut username_string = format_utils::value_to_string(username_oject.to_owned());
		username_string.remove(0);
		username_string.remove( username_string.len() - 1 );
	

		let email_object = response_object.get("email").expect("email not found");
		let mut email_string = format_utils::value_to_string(email_object.to_owned());
		email_string.remove(0);
		email_string.remove( email_string.len() - 1 );


		let password_object = response_object.get("password").expect("password not found");
		let mut password_sting = format_utils::value_to_string(password_object.to_owned());
		password_sting.remove(0);
		password_sting.remove( password_sting.len() - 1 );
		let user = User {
			username: username_string,
			email:  email_string,
			password: password_sting,
		};
		user
	}

}


#[cfg(test)]
mod test_user {
    use crate::User;
	use pwhash::bcrypt;

    #[test]
    fn test_create_obj() {
		let username = "username";
		let email = "email";
		let password = "password";
		let user = User::create_obj(username, email, password);
		assert_eq!(email, user.email);
		assert_eq!(username, user.username);
		assert_ne!(password, user.password);
		let is_valid_passsword = bcrypt::verify(password, &user.password);
		assert!(is_valid_passsword, "The password hash is not valid");
    }

	#[test]
	fn test_create_query(){
		let user = User::create_obj("username", "email", "password");
		let password = user.password.to_owned();
		let expected_query = format!("
			CREATE user SET
			username = 'username',
			email = 'email',
			password = '{}',
			created_on = time::now()
			;", password);
		let actual_query = user.generate_create_query();
		assert_eq!(expected_query, actual_query);
	}
}


pub struct Database{
	datastore: Datastore,
	surreal_ns: String,
	surreal_db: String,
	session: Session,
}


impl Database {
	pub async fn connect(path: &str, ns: & str, db: & str) -> Result<Database, Error> {
		let dt = Datastore::new(path).await?;
		let session = Session::for_kv();
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

	pub async fn create_user(&mut self, user: User) -> Result<Object, Error>{
		let query = user.generate_create_query();
		let raw_responses = self.excute(query.as_ref()).await?;
		let formatted_reponse = format_utils::vec_response_to_query_response(raw_responses);
		Ok(formatted_reponse)
	}

	pub async fn login(&mut self, username: &str, password: &str) -> Result< Object, Error>{
		let fetch_user_query = format!("
			SELECT * FROM user WHERE username = {} AND password = {};
		", username, password);
		let raw_response = self.excute(&fetch_user_query).await?;
		let formatted_response = format_utils::vec_response_to_query_response(raw_response);
		Ok(formatted_response)
	}

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
		db.create_user(
			User::create_obj("username", "email", "password")
		).await?;

		let user = db.login("username", "password").await?;
		// dbg!(&user);

		Ok(())
	}

	#[tokio::test]
    async fn test_user_response_to_user_struct() -> Result<(), Error> {
		let mut db = Database::connect("memory", "test", "test").await?;
		let response = db.create_user(
			User::create_obj("username", "email", "password")
		).await?;

		let user_struct = User::from_object_response(response);
		assert_eq!(user_struct.username, "username");
		assert_eq!(user_struct.email, "email");
		dbg!(&user_struct.password);
		let is_valid_password = bcrypt::verify("password", &user_struct.password);
		assert!(
			is_valid_password,
			"Not a valid a password"
		);

		Ok(())
	}

}
