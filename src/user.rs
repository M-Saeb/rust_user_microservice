use pwhash::bcrypt;
use surrealdb::sql::{Object};
use crate::utils as format_utils;

fn hash_string(raw_password: &str) -> String{
	let hash_string = bcrypt::hash(raw_password).unwrap();
	hash_string
}

#[derive(Debug)]
pub struct User{
	pub id: Option<String>,
	pub username: String,
	pub email: String,
	pub password: String
}

impl User {
	pub fn generate_get_user_by_username_query(username: &str) -> String {
		let query = format!(
			"SELECT * FROM user WHERE username = '{}';",
			username);
		query
	}

	pub fn generate_get_user_by_email_query(email: &str) -> String {
		let query = format!(
			"SELECT * FROM user WHERE email = '{}';",
		email);
		query
	}

	pub fn generate_create_query(&self) -> String {
		let query = format!("
			CREATE user SET
			username = '{}',
			email = '{}',
			password = '{}',
			created_on = time::now()
			;", self.username, self.email, self.password);
		query
	}

	pub fn generate_delete_query(user_id: &str) -> String {
		let query = format!(
			"DELETE user WHERE id = '{}';",
			user_id
		);
		query
	}

	pub fn generate_update_query(&self) -> String {
		assert!(
			self.id.as_ref().is_some(),
			"id attribute must have value for you to run generate_update_query()"
		);
		let query = format!(
			"UPDATE user:{} SET
			username = '{}',
			email = '{}',
			password = '{}';",
			&self.id.as_ref().unwrap(), &self.username, &self.email, &self.password
		);
		query
	}

	pub fn set_password(&mut self, raw_password: &str){
		let hashed_password = hash_string(raw_password);
		self.password = hashed_password;
	}

	pub fn create_obj(username: &str, email: &str, raw_password: &str) -> User {
		let hashed_password = hash_string(raw_password);
		let new_user = User {
			id: None,
			username: username.to_owned(),
			email: email.to_owned(),
			password: hashed_password,
		};
		new_user
	}

	pub fn from_object_response(response_object: Object) -> User {
		let id_object = response_object.get("id").expect("id not found");
		let mut id_string = format_utils::value_to_string(id_object.to_owned());

		let username_oject = response_object.get("username").expect("username not found");
		let mut username_string = format_utils::value_to_string(username_oject.to_owned());

		let email_object = response_object.get("email").expect("email not found");
		let mut email_string = format_utils::value_to_string(email_object.to_owned());

		let password_object = response_object.get("password").expect("password not found");
		let mut password_sting = format_utils::value_to_string(password_object.to_owned());
		let user = User {
			id: Some(id_string),
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

	#[test]
	fn test_delete_query(){
		let actual_query = User::generate_delete_query("random_id");
		let expected_query = "DELETE user WHERE id = 'random_id';";
		assert_eq!(expected_query.to_string(), actual_query);
	}

	#[test]
	fn test_update_query(){
		let user = User{
			id: Some("some_id".to_string()),
			email: "email".to_string(),
			username: "username".to_string(),
			password: "password".to_string(),
			
		};
		let actual_query = user.generate_update_query();
		let expected_query = 
			"UPDATE user:some_id SET
			username = 'username',
			email = 'email',
			password = 'password';";
		assert_eq!(expected_query.to_string(), actual_query);
	}

	#[test]
	fn test_get_user_by_username_query(){
		let expected_query = "SELECT * FROM user WHERE username = 'username';";
		let actual_query = User::generate_get_user_by_username_query("username");
		assert_eq!(expected_query, actual_query);
	}

	#[test]
	fn test_get_user_by_email_query(){
		let expected_query = "SELECT * FROM user WHERE email = 'test@email.com';";
		let actual_query = User::generate_get_user_by_email_query("test@email.com");
		assert_eq!(expected_query, actual_query);
	}
}

