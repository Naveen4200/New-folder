from database import Sessionlocal


def api_response(status_code, data=None, message: str = None, total: int = 0, count: int = 0):
    response_data = {"data": data, "message": message, "status_code": status_code, "total": total, "count": count}
    filtered_response = {key: value for key, value in response_data.items() if value is not None or 0}
    return filtered_response


def get_db():
    db = Sessionlocal()
    try:
        yield db
    finally:
        db.close()
