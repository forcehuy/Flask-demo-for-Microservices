from flask import Blueprint
from datetime import datetime

main = Blueprint('main', __name__)

from . import views, errors
from ..models import Permission


@main.app_context_processor
def inject_permissions():
    return dict(Permission=Permission)


@main.app_context_processor
def inject_now():
    return {'now': datetime.utcnow()}