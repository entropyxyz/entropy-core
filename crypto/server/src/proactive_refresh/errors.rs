use std::{io::Cursor, string::FromUtf8Error};

use rocket::{
    http::Status,
    response::{Responder, Response},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RefreshErr {

}

impl<'r, 'o: 'r> Responder<'r, 'o> for RefreshErr {
    fn respond_to(self, _request: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        let body = format!("{self}").into_bytes();
        Response::build()
            .sized_body(body.len(), Cursor::new(body))
            .status(Status::InternalServerError)
            .ok()
    }
}
