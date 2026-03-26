use attackstr::{
    mutate_all, mutate_case, mutate_encoding_mix, mutate_sql_comments, mutate_whitespace,
};

fn main() {
    let payload = "UNION SELECT 1";

    println!("case mutations:");
    for variant in mutate_case(payload) {
        println!("  {variant}");
    }

    println!("whitespace mutations:");
    for variant in mutate_whitespace(payload) {
        println!("  {variant}");
    }

    println!("encoding mix mutations:");
    for variant in mutate_encoding_mix(payload, &["url_encode", "unicode", "html_entities"]) {
        println!("  {variant}");
    }

    println!("sql comment mutations:");
    for variant in mutate_sql_comments(payload) {
        println!("  {variant}");
    }

    println!("all mutations:");
    for variant in mutate_all("<script>alert(1)</script>").into_iter().take(10) {
        println!("  {variant}");
    }
}
