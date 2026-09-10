"""Initial schema creation for MailRecon AI.

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-09-10 23:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'analysts',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('display_name', sa.String(length=255), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email'),
    )

    op.create_table(
        'cases',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('status', sa.Enum('pending', 'processing', 'completed', 'failed', name='casestatus'), nullable=False),
        sa.Column('original_sha256', sa.String(length=64), nullable=False),
        sa.Column('original_size', sa.Integer(), nullable=True),
        sa.Column('filename', sa.String(length=255), nullable=True),
        sa.Column('storage_key', sa.Text(), nullable=False),
        sa.Column('analyst_id', sa.Uuid(), nullable=False),
        sa.Column('metadata_json', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['analyst_id'], ['analysts.id']),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'findings',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('case_id', sa.Uuid(), nullable=False),
        sa.Column('detector', sa.String(), nullable=False),
        sa.Column('severity', sa.Enum('info', 'low', 'medium', 'high', 'critical', name='severitylevel'), nullable=False),
        sa.Column('title', sa.String(), nullable=True),
        sa.Column('detail', sa.Text(), nullable=True),
        sa.Column('evidence_ref', sa.String(), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=True),
        sa.Column('raw_evidence', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_table(
        'indicators',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('case_id', sa.Uuid(), nullable=False),
        sa.Column('kind', sa.Enum('email', 'domain', 'ip', 'url', 'hash', 'qr_url', name='indicatorkind'), nullable=False),
        sa.Column('value', sa.Text(), nullable=False),
        sa.Column('context', sa.Text(), nullable=True),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('case_id', 'kind', 'value', name='uix_case_kind_value'),
    )

    op.create_table(
        'parsed_emails',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('case_id', sa.Uuid(), nullable=False),
        sa.Column('headers_json', sa.JSON(), nullable=True),
        sa.Column('body_text', sa.Text(), nullable=True),
        sa.Column('body_html', sa.Text(), nullable=True),
        sa.Column('attachments_json', sa.JSON(), nullable=True),
        sa.Column('urls_json', sa.JSON(), nullable=True),
        sa.Column('auth_results_json', sa.JSON(), nullable=True),
        sa.Column('received_chain_json', sa.JSON(), nullable=True),
        sa.Column('parsed_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('case_id'),
    )

    op.create_table(
        'reports',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('case_id', sa.Uuid(), nullable=False),
        sa.Column('format', sa.Enum('html', 'json', name='reportformat'), nullable=False),
        sa.Column('storage_key', sa.Text(), nullable=False),
        sa.Column('integrity_sha256', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['cases.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    op.drop_table('reports')
    op.drop_table('parsed_emails')
    op.drop_table('indicators')
    op.drop_table('findings')
    op.drop_table('cases')
    op.drop_table('analysts')
