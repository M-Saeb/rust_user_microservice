use surrealdb::sql::{Object};
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
	pub password: String
}

impl User {
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

