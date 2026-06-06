//! Case immutability guard — sealed cases are read-only.

pub fn is_case_sealed(case_id: &str) -> Result<bool, String> {
    let db = crate::db::conn();
    let status: String = db
        .query_row(
            "SELECT status FROM cases WHERE id = ?1",
            [case_id],
            |row| row.get(0),
        )
        .map_err(|e| format!("Case not found: {e}"))?;
    Ok(status == "sealed")
}

pub fn ensure_case_mutable(case_id: &str) -> Result<(), String> {
    if is_case_sealed(case_id)? {
        return Err(
            "Case is sealed — analysis is read-only. No further modifications allowed.".into(),
        );
    }
    Ok(())
}
