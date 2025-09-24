from models.audit_logs_model import insert_audit_log

def log_action(user_id, action, metadata=None):
    insert_audit_log(
        user_id=user_id,
        action=action,
        metadata=metadata
    )