//! Admin-facing response DTOs relocated from the Control domain model
//! (`Control.InsightCenterApp.AdminFacingInterface`). They are view models that
//! stitch together Observed / Security domain data for the center admin API.

#[derive(
    Debug, Clone, PartialEq, ::serde::Serialize, ::serde::Deserialize, ::jumo_derive::Jumo,
)]
#[jumo(
    kind = "message",
    role = "response",
    domain = "Control",
    module = "Control.InsightCenterApp.AdminFacingInterface"
)]
pub struct AdminHostInventoryReturned {
    pub hosts: Vec<wist_observed::HostInventory>,
}

#[derive(
    Debug, Clone, PartialEq, ::serde::Serialize, ::serde::Deserialize, ::jumo_derive::Jumo,
)]
#[jumo(
    kind = "message",
    role = "response",
    domain = "Control",
    module = "Control.InsightCenterApp.AdminFacingInterface"
)]
pub struct AdminNetworkTopologyReturned {
    pub segments: Vec<wist_observed::NetworkSegment>,
}

#[derive(
    Debug, Clone, PartialEq, ::serde::Serialize, ::serde::Deserialize, ::jumo_derive::Jumo,
)]
#[jumo(
    kind = "message",
    role = "response",
    domain = "Control",
    module = "Control.InsightCenterApp.AdminFacingInterface"
)]
pub struct AdminServiceTopologyReturned {
    pub services: Vec<wist_observed::ServiceEntity>,
}

#[derive(
    Debug, Clone, PartialEq, ::serde::Serialize, ::serde::Deserialize, ::jumo_derive::Jumo,
)]
#[jumo(
    kind = "message",
    role = "response",
    domain = "Control",
    module = "Control.InsightCenterApp.AdminFacingInterface"
)]
pub struct AdminSoftwareVulnerabilitiesReturned {
    pub findings: Vec<wist_security::SoftwareVulnerabilityFinding>,
}
