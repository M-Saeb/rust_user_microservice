use surrealdb::sql::{Object};
use crate::utils as format_utils;


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
			;", self.user, self.key);
		query
	}

	pub fn create_obj(user: &str, key: &str) -> Session {
		let new_session = Session {
			user: user.to_owned(),
			key: key.to_owned(),
		};
		new_session
	}

	pub fn from_object_response(response_object: Object) -> Session {
		let user_object = response_object.get("user").expect("user not found");
		let mut user_string = format_utils::value_to_string(user_object.to_owned());
		user_string.remove(0);
		user_string.remove( user_string.len() - 1 );

		let key_object = response_object.get("key").expect("key not found");
		let mut key_string = format_utils::value_to_string(key_object.to_owned());
		key_string.remove(0);
		key_string.remove( key_string.len() - 1 );

		let session = Session {
			user: user_string,
			key: key_string
		};
		session
	}

}


#[cfg(test)]
mod test_session {
    use crate::Session;
	use pwhash::bcrypt;

    #[test]
    fn test_create_obj() {
    }

	#[test]
	fn test_create_query(){
	}
}

