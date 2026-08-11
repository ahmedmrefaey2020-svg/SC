import uuid
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, Float, DateTime, Text, ForeignKey
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class BlockedIP(Base):
    __tablename__ = "blocked_ips"
    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    ip_address = Column(String, unique=True, index=True, nullable=False)
    protocol = Column(String, nullable=False, default="TCP")
    port = Column(Integer, nullable=False, default=0)
    src_bytes = Column(Float, nullable=False, default=0.0)
    blocked_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    reason = Column(String, nullable=False, default="MANUAL")
    attack_type = Column(String, nullable=False, default="Unknown")


class NetworkFlow(Base):
    __tablename__ = "network_flows"
    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    time = Column(String, nullable=False)
    src = Column(String, nullable=False, index=True)
    dest = Column(String, nullable=False)
    proto = Column(String, nullable=False)
    duration = Column(String, default="0.0")
    packets = Column(Integer, default=1)
    is_attack = Column(Boolean, default=False, nullable=False)
    label = Column(String, nullable=False, default="Normal")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class SystemSetting(Base):
    __tablename__ = "system_settings"
    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    org_name = Column(String, default="Sentinel IDS")
    admin_email = Column(String, default="admin@network.local")
    timezone = Column(String, default="UTC")
    push_notifications = Column(Boolean, default=True)
    email_alerts = Column(Boolean, default=True)
    auto_block = Column(Boolean, default=True)
    block_mode = Column(String, default="auto")
    active_model = Column(String, default="lstm")
    confidence_threshold = Column(Integer, default=85)
    monitoring_mode = Column(String, default="scapy")
    api_key = Column(String, default="")
    report_interval_minutes = Column(Integer, default=30)
    theme_mode = Column(String, default="dark")
    smtp_server = Column(String, default="")
    smtp_port = Column(Integer, default=587)
    smtp_user = Column(String, default="")
    smtp_pass = Column(String, default="")
    smtp_use_tls = Column(Boolean, default=True)
    linked_site_url = Column(String, default="")
    linked_site_token = Column(String, default="")


class LLMChatSession(Base):
    """Stores individual LLM chat sessions with UUID primary key."""
    __tablename__ = "llm_chat_sessions"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    title = Column(String(255), nullable=False, default="New Chat")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    messages = relationship("LLMChatMessage", back_populates="session", cascade="all, delete-orphan", order_by="LLMChatMessage.created_at")


class LLMChatMessage(Base):
    """Stores individual messages within a chat session."""
    __tablename__ = "llm_chat_messages"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    session_id = Column(String(36), ForeignKey("llm_chat_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String(20), nullable=False)  # 'user' or 'assistant'
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    session = relationship("LLMChatSession", back_populates="messages")


class AutoTrainEvent(Base):
    """Logs automatic model retraining events when selected model fails."""
    __tablename__ = "auto_train_events"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    trigger_reason = Column(String, nullable=False, default="Model divergence detected")
    models_trained = Column(String, nullable=False, default="lstm,rf,xgboost,lr")
    triggered_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    result = Column(String, nullable=False, default="success")


class HoneypotLog(Base):
    """Real intrusion attempts captured by decoy honeypot services. Rows are inserted
    only by the actual honeypot listener via log_honeypot_attempt() — never seeded."""
    __tablename__ = "honeypot_logs"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    attacker_ip = Column(String, nullable=False, index=True)
    decoy_service = Column(String, nullable=False)
    port = Column(Integer, nullable=False, default=0)
    payload_attempted = Column(Text, default="")
    action_taken = Column(String, default="Logged")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)


class IncidentEvent(Base):
    """Forensic incident timeline. Rows are inserted only by real system activity
    (SOAR playbook triggers, red-team simulations, auto-block actions) — never seeded."""
    __tablename__ = "incident_events"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    event_type = Column(String, nullable=False)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False, default="Info")
    details = Column(Text, default="")
    source = Column(String, default="system")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)


class Playbook(Base):
    """SOAR Automation Playbook — defines condition-action security response rules."""
    __tablename__ = "playbooks"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, default="")
    # Trigger condition fields
    condition_metric = Column(String(100), nullable=False)   # e.g. 'packet_rate', 'risk_score', 'attack_type'
    condition_operator = Column(String(20), nullable=False)  # '>', '<', '>=', '<=', '==', 'contains'
    condition_value = Column(String(255), nullable=False)    # threshold value as string
    # Action fields
    action_type = Column(String(100), nullable=False)        # 'block_ip', 'send_email', 'webhook', 'log_only'
    action_config = Column(Text, default="{}")               # JSON config for the action
    # Webhook configuration
    webhook_url = Column(String(500), default="")
    webhook_method = Column(String(10), default="POST")      # POST or GET
    # Status & audit
    enabled = Column(Boolean, default=True)
    trigger_count = Column(Integer, default=0)
    last_triggered = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)