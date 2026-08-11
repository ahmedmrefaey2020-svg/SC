from pydantic import BaseModel, Field, computed_field, field_validator, model_validator
import re

_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


class SettingsSchema(BaseModel):
    orgName: str = Field(..., min_length=1, max_length=100)
    adminEmail: str = Field(default="admin@network.local", max_length=200)
    timezone: str = Field(default="UTC", max_length=50)
    pushNotifications: bool = Field(default=True)
    emailAlerts: bool = Field(default=True)
    autoBlock: bool = Field(default=True)
    blockMode: str = Field(default="auto", pattern="^(auto|manual)$")
    activeModel: str = Field(..., pattern="^(lstm|rf|ml|xgboost|lr)$")
    confidence: int = Field(..., ge=1, le=100)
    token: str = Field(default="", max_length=256)
    monitoringMode: str = Field(default="scapy", pattern="^(scapy|api_agent)$")
    reportInterval: int = Field(default=30, ge=1, le=1440)
    themeMode: str = Field(default="dark")
    smtpServer: str = Field(default="")
    smtpPort: int = Field(default=587, ge=1, le=65535)
    smtpUser: str = Field(default="")
    smtpPass: str = Field(default="")
    smtpUseTls: bool = Field(default=True)
    linkedSiteUrl: str = Field(default="")
    linkedSiteToken: str = Field(default="")

    @model_validator(mode="after")
    def sync_mode_with_token(self):
        token = (self.token or "").strip()
        if token:
            self.token = token
            self.monitoringMode = "api_agent"
        else:
            self.token = ""
            self.monitoringMode = "scapy"
        if self.activeModel == "ml":
            self.activeModel = "rf"
        self.autoBlock = (self.blockMode == "auto")
        return self



class BlockIPSchema(BaseModel):
    ip: str = Field(..., min_length=7, max_length=45)

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        if not _IP_RE.match(v):
            raise ValueError("Invalid IP address format")
        return v


class ExternalFlowRecord(BaseModel):
    src: str = Field(default="0.0.0.0")
    dest: str = Field(default="0.0.0.0")
    port: int = Field(default=0, ge=0, le=65535)
    proto: str = Field(default="TCP")
    flow_duration: float = Field(default=0.0, alias="Flow Duration")
    flow_iat_mean: float = Field(default=0.0, alias="Flow IAT Mean")
    flow_iat_max: float = Field(default=0.0, alias="Flow IAT Max")
    flow_iat_min: float = Field(default=0.0, alias="Flow IAT Min")
    tot_len_fwd_pkts: float = Field(default=0.0, alias="TotLen Fwd Pkts")
    tot_len_bwd_pkts: float = Field(default=0.0, alias="TotLen Bwd Pkts")
    fwd_pkt_len_max: float = Field(default=0.0, alias="Fwd Pkt Len Max")
    fwd_pkt_len_mean: float = Field(default=0.0, alias="Fwd Pkt Len Mean")
    bwd_pkt_len_max: float = Field(default=0.0, alias="Bwd Pkt Len Max")
    bwd_pkt_len_mean: float = Field(default=0.0, alias="Bwd Pkt Len Mean")
    pkt_size_avg: float = Field(default=0.0, alias="Pkt Size Avg")
    fin_flag_cnt: float = Field(default=0.0, alias="FIN Flag Cnt")
    syn_flag_cnt: float = Field(default=0.0, alias="SYN Flag Cnt")
    rst_flag_cnt: float = Field(default=0.0, alias="RST Flag Cnt")
    psh_flag_cnt: float = Field(default=0.0, alias="PSH Flag Cnt")
    ack_flag_cnt: float = Field(default=0.0, alias="ACK Flag Cnt")
    urg_flag_cnt: float = Field(default=0.0, alias="URG Flag Cnt")
    init_fwd_win_byts: float = Field(default=0.0, alias="Init Fwd Win Byts")
    init_bwd_win_byts: float = Field(default=0.0, alias="Init Bwd Win Byts")
    flow_byts_s: float = Field(default=0.0, alias="Flow Byts/s")
    flow_pkts_s: float = Field(default=0.0, alias="Flow Pkts/s")
    fwd_pkt_len_std: float = Field(default=0.0, alias="Fwd Pkt Len Std")
    pkt_len_var: float = Field(default=0.0, alias="Pkt Len Var")
    fwd_header_len: float = Field(default=0.0, alias="Fwd Header Len")

    model_config = {"populate_by_name": True}

    def to_feature_list(self) -> list[float]:
        return [
            self.flow_duration, self.flow_iat_mean, self.flow_iat_max,
            self.flow_iat_min, self.tot_len_fwd_pkts, self.tot_len_bwd_pkts,
            self.fwd_pkt_len_max, self.fwd_pkt_len_mean, self.bwd_pkt_len_max,
            self.bwd_pkt_len_mean, self.pkt_size_avg, self.fin_flag_cnt,
            self.syn_flag_cnt, self.rst_flag_cnt, self.psh_flag_cnt,
            self.ack_flag_cnt, self.urg_flag_cnt, self.init_fwd_win_byts,
            self.init_bwd_win_byts, self.flow_byts_s, self.flow_pkts_s,
            self.fwd_pkt_len_std, self.pkt_len_var, self.fwd_header_len,
        ]

    def metadata(self) -> dict:
        return {
            "src": self.src,
            "dest": self.dest,
            "port": self.port,
            "proto": (self.proto or "TCP").upper(),
            "src_bytes": float(self.tot_len_fwd_pkts),
        }


class ExternalIngestPayload(BaseModel):
    records: list[ExternalFlowRecord] = Field(..., min_length=1, max_length=5000)


class NetworkFlowOut(BaseModel):
    id: str | int
    time: str
    src: str
    dest: str
    proto: str
    duration: str
    packets: int
    is_attack: bool
    label: str

    model_config = {"from_attributes": True}

    @computed_field
    @property
    def isAttack(self) -> bool:
        return self.is_attack
