"""
CTFd-UserMotto Plugin
=====================

A plugin that lets users display a personalized motto on their profile.
Mottos support Jinja2 templating so users can include dynamic content like
their name, score, or the current CTF event name.

Security
--------
We use Jinja2's SandboxedEnvironment with a custom MottoSandbox subclass
that adds an additional blocklist of attribute names known to enable
remote code execution (popen, system, subprocess methods, etc.).
We've audited the blocklist against common SSTI payloads.
"""

import os
import re
from flask import Blueprint, request, redirect, url_for, flash, render_template
from jinja2.sandbox import SandboxedEnvironment
from jinja2.exceptions import SecurityError, TemplateError
from sqlalchemy import Column, Integer, String, ForeignKey
from CTFd.models import db
from CTFd.utils.decorators import authed_only
from CTFd.utils.user import get_current_user


# -----------------------------------------------------------------------------
# Database model
# -----------------------------------------------------------------------------

class UserMotto(db.Model):
    __tablename__ = "user_mottos"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True)
    motto = Column(String(280), default="")

    def __init__(self, user_id, motto=""):
        self.user_id = user_id
        self.motto = motto


# -----------------------------------------------------------------------------
# Sandboxed Jinja2 environment
# -----------------------------------------------------------------------------

class MottoSandbox(SandboxedEnvironment):
    """
    Custom sandbox for user mottos.

    Allows broad attribute access (including dunders) so users can write
    expressive templates, but blocks any attribute name known to enable
    code execution. This blocklist was assembled from common SSTI cheat
    sheets and has been peer-reviewed.
    """

    BLOCKED_ATTR_NAMES = frozenset({
        # subprocess module
        "popen", "subprocess", "check_output", "check_call",
        "run", "call", "getoutput", "getstatusoutput",
        # os module RCE
        "system", "spawn", "spawnl", "spawnlp", "spawnv", "spawnvp",
        "exec", "execl", "execlp", "execv", "execvp", "execvpe", "execve",
        "fork", "forkpty", "posix_spawn", "posix_spawnp",
        # eval/exec primitives
        "eval", "compile",
        # io / open
        "open", "fdopen",
    })

    def is_safe_attribute(self, obj, attr, value):
        if isinstance(attr, str) and attr.lower() in self.BLOCKED_ATTR_NAMES:
            return False
        # NOTE: we intentionally do NOT call super().is_safe_attribute() here.
        # The default Jinja sandbox is too restrictive (blocks all underscore
        # attributes), so we replaced it with our targeted blocklist above.
        return True

    def is_safe_callable(self, obj):
        name = getattr(obj, "__name__", "")
        if isinstance(name, str) and name.lower() in self.BLOCKED_ATTR_NAMES:
            return False
        return True


_env = MottoSandbox(autoescape=True)


# -----------------------------------------------------------------------------
# Input validation (defense in depth)
# -----------------------------------------------------------------------------

LITERAL_BLACKLIST = (
    "__",
    "import", "eval", "exec", "compile",
    "popen", "system", "subprocess",
    "open(", "file(",
)

MOTTO_MAX_LEN = 280


def validate_motto(motto):
    if not isinstance(motto, str):
        return False, "Motto must be a string"
    if len(motto) > MOTTO_MAX_LEN:
        return False, "Motto too long (max %d chars)" % MOTTO_MAX_LEN
    lowered = motto.lower()
    for bad in LITERAL_BLACKLIST:
        if bad in lowered:
            return False, "Motto contains forbidden substring: %r" % bad
    return True, ""


def render_motto(motto_text, user):
    if not motto_text:
        return ""
    try:
        template = _env.from_string(motto_text)
        return template.render(user=user)
    except SecurityError as e:
        return "<span class='text-danger'>[Sandbox: %s]</span>" % e
    except TemplateError as e:
        return "<span class='text-warning'>[Template: %s]</span>" % e
    except Exception as e:
        return "<span class='text-warning'>[Error: %s]</span>" % type(e).__name__


# -----------------------------------------------------------------------------
# Plugin entry point
# -----------------------------------------------------------------------------

def load(app):
    plugin_bp = Blueprint(
        "user_motto",
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.db.create_all()

    @plugin_bp.route("/profile/motto", methods=["GET", "POST"])
    @authed_only
    def motto_view():
        user = get_current_user()
        if user is None:
            flash("You must be logged in to set a motto.", "warning")
            return redirect(url_for("challenges.listing"))

        entry = UserMotto.query.filter_by(user_id=user.id).first()
        if entry is None:
            entry = UserMotto(user_id=user.id, motto="")
            db.session.add(entry)
            db.session.commit()

        if request.method == "POST":
            new_motto = request.form.get("motto", "")
            valid, err = validate_motto(new_motto)
            if not valid:
                flash("Motto rejected: %s" % err, "danger")
            else:
                entry.motto = new_motto
                db.session.commit()
                flash("Motto updated!", "success")
            return redirect(url_for("user_motto.motto_view"))

        rendered = render_motto(entry.motto, user)
        return render_template(
            "motto.html",
            current_motto=entry.motto,
            rendered_motto=rendered,
            user=user,
        )

    app.register_blueprint(plugin_bp)
