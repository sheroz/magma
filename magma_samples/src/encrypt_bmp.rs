use std::env;
use std::fs::File;
use std::path::Path;
use image::{GenericImageView, ImageFormat};

pub fn encrypt_bmp(source: &Path) {
    let img = image::open(source).unwrap();
}