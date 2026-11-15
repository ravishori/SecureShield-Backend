"""sms_sender_registry: expression index on upper(header); warrior_audit_logs: table comment

Revision ID: y0z1a2b3c4d5
Revises: x9y0z1a2b3c4

Additive only. Nothing is dropped, rewritten, updated or deleted.

* ``ix_sms_sender_header_upper`` is an EXPRESSION index on ``upper(header)``. The only lookup of the sender registry
  (``app/services/sms_header_validator.py``) is ``WHERE upper(header) = :x``, which a plain index on ``header`` cannot serve, so
  every lookup would scan the whole table. The model used to declare a plain index of this name (it was never created in any
  database); it now declares the expression. The existing plain index ``ix_sms_sender_registry_header`` is not touched.
* ``warrior_audit_logs`` gets the table comment the model has always carried ("Append-only ..."). Catalog metadata only.

Downgrade removes exactly those two objects and nothing else.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "y0z1a2b3c4d5"
down_revision: Union[str, None] = "x9y0z1a2b3c4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

AUDIT_COMMENT = "Append-only. Do not UPDATE or DELETE rows here."


def upgrade() -> None:
    op.create_index(
        "ix_sms_sender_header_upper",
        "sms_sender_registry",
        [sa.text("upper(header)")],
    )
    op.create_table_comment("warrior_audit_logs", AUDIT_COMMENT)


def downgrade() -> None:
    op.drop_table_comment("warrior_audit_logs", existing_comment=AUDIT_COMMENT)
    op.drop_index("ix_sms_sender_header_upper", table_name="sms_sender_registry")
