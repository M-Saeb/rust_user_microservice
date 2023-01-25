use surrealdb::sql::{Object};
use crate::utils as format_utils;
use random_string::generate;

pub fn get_all_chars() -> String{
	let charset = String::from("1234567890abcdefghijlkmnopqrstuvwxyz");
	return charset
}


#[derive(Debug)]
pub struct Session{
	pub user: String,
	pub key: String,
}

impl Session {
	pub fn generate_create_query(&self) -> String {
		let query = format!("
			CREATE session SET
			user = '{}',
			key = '{}',
			created_on = time::now(),
			;", self.user, self.key);
		query
	}

	pub fn create_obj(user: &str) -> Session {
		let key = generate(32, get_all_chars());
		let new_session = Session {
			user: user.to_owned(),
			key: key,
		};
		new_session
	}

	pub fn from_object_response(response_object: Object) -> Session {
		let user_object = response_object.get("user").expect("user not found");
		let mut user_string = format_utils::value_to_string(user_object.to_owned());

		let key_object = response_object.get("key").expect("key not found");
		let mut key_string = format_utils::value_to_string(key_object.to_owned());

		let session = Session {
			user: user_string,
			key: key_string
		};
		session
	}

}


#[cfg(test)]
mod test_session {
	use super::get_all_chars;
    use crate::{Session};
	use random_string::generate;

    #[test]
    fn test_create_obj() {
		let user_id = generate(10, get_all_chars());
		let session = Session::create_obj(user_id.as_str());
		assert_eq!(session.user, user_id);
		assert_eq!(session.key.len(), 32);
    }

	#[test]
	fn test_create_query(){
		let user_id = "some_user_id";
		let session = Session::create_obj(user_id);
		let expected_query = format!("
			CREATE session SET
			user = 'some_user_id',
			key = '{}',
			created_on = time::now(),
			;", session.key);
		assert_eq!(expected_query, session.generate_create_query());
	}
}

