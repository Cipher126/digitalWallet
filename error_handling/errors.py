class AppError(Exception):
    def __init__(self, message="An error occurred", status_code=400, error_code="app_error", details=None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        self.details = details

class ValidationError(AppError):
    def __init__(self, message="Validation failed", details=None):
        super().__init__(message, 400, "Validation_error",details)

class UnauthorizedError(AppError):
    def __init__(self, message="Unauthorized", details=None):
        super().__init__(message, 401, "unauthorized", details)

class ForbiddenError(AppError):
    def __init__(self, message="Forbidden", details=None):
        super().__init__(message, 403, "forbidden", details)

class NotFoundError(AppError):
    def __init__(self, message="Resource not found", details=None):
        super().__init__(message, 404, "not_found", details)

class ConflictError(AppError):
    def __init__(self, message="Conflict", details=None):
        super().__init__(message, 409, "conflict", details)

class InsufficientFundsError(AppError):
    def __init__(self, message="Insufficient funds", details=None):
        super().__init__(message, 400, "insufficient_funds", details)

class InsufficientDataError(AppError):
    def __init__(self, message="Not enough data provided", details=None):
        super().__init__(message, 400, "required_field(s)_missing", details)

class LockoutError(AppError):
    def __init__(self, message="Account temporarily locked", details=None):
        super().__init__(message, 429, "lockout", details)