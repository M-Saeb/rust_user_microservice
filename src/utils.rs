use surrealdb::Datastore;
use surrealdb::Session;
use surrealdb::Response;
use surrealdb::Error;
use surrealdb::Val;
use surrealdb::sql::{Value, Array, Object};


fn vec_response_to_item<'a>(vec_response: &'a Vec<Response>, index: usize) -> &'a Response{
	let second_response = &vec_response[index];
	second_response
}

fn response_to_value(response: &Response) -> Value{
	let value_obj = response.result.as_ref().expect("Something went wrong");
	value_obj.to_owned()
}

fn value_to_array(value: Value) -> Array{
	let array = match value{
		Value::Array(a) => a,
		_ => panic!("Expeceted Array !! got something else"),
	};
	array
}

fn array_to_item(array: Array, index: usize) -> Value{
	let value = &array[0];
	value.to_owned()
}

fn value_to_object(value: Value) -> Object {
	let object = match value{
		Value::Object(a) => a,
		_ => panic!("Expeceted Object !! got something else"),
	};
	object
}

pub fn value_to_string(value: Value) -> String{
	let mut strand = match value{
		Value::Strand(a) => a.to_string(),
		_ => panic!("Expeceted Strand !! got something else"),
	};
	strand
}

pub fn vec_response_to_query_response(vec_response: Vec<Response>) -> Object {
	let result = { 
		let response = vec_response_to_item(&vec_response, 1);
		let response_value = response_to_value(response);

		let response_value_array = value_to_array(response_value);
		let response_value_array_item = array_to_item(response_value_array, 0);
		let create_result = value_to_object(response_value_array_item);
		create_result
	};

	result
}