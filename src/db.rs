use surrealdb::Datastore;
use surrealdb::Session;
use surrealdb::Response;
use surrealdb::Error;
use surrealdb::sql::{Value, Object};
use pwhash::bcrypt;


fn hash_string(raw_password: &str) -> String{
	let hash_string = bcrypt::hash(raw_password).unwrap();
	hash_string
}

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
		let new_user = User {
			username: username.to_owned(),
			email: email.to_owned(),
			password: hashed_password,
		};
		new_user
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

		let result = { 
			let raw_create_response = &raw_responses[1];
			let create_results = raw_create_response.result.as_ref().expect("Something went wrong");
	
			let create_first_clean = match create_results{
				Value::Array(a) => a,
				_ => panic!("This shoundn't have happend"),
			};
			let create_second_clean = &create_first_clean[0];	

			match create_second_clean{
				Value::Object(a) => a,
				_ => panic!("This shoundn't have happend"),
			}
		};

		Ok(result.to_owned())
	}

}


#[cfg(test)]
mod test_db {
    use crate::{Database, User};
	use surrealdb::Error;

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
		dbg!(&response);
		let username = response.get("username").expect("No Username found");
		dbg!(username);
		// println!("response = {:?}", response);
		Ok(())
    }
}
