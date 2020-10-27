package goarcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

//------------------------------------------------------------------------------
// Structures
//------------------------------------------------------------------------------

// Incident is a RSA security incident
type Incident struct {
	SecurityIncidentsID                  int           `json:"Security_Incidents_Id"`
	ActorTacticsTechniques               []interface{} `json:"Actor_Tactics__Techniques"`
	AffectedFacility                     []interface{} `json:"Affected_Facility"`
	AlwaysTrue                           []string      `json:"alwaysTrue"`
	Archive                              []interface{} `json:"Archive"`
	AttachToInfoSecBriefing              []interface{} `json:"Attach_to_InfoSec_Briefing"`
	AttackCategory                       []interface{} `json:"Attack_Category"`
	AutomaticIncidentHandlerAccess       []string      `json:"Automatic_Incident_Handler_Access"`
	AvailabilityCompromiseRating         []interface{} `json:"Availability_Compromise_Rating"`
	AvailabilityCompromised              []interface{} `json:"Availability_Compromised"`
	AvailabilityImpactNotes              interface{}   `json:"Availability_Impact_Notes"`
	BusinessImpactNotes                  interface{}   `json:"Business_Impact_Notes"`
	BusinessLossRating                   []string      `json:"Business_Loss_Rating"`
	BusinessLossType                     []interface{} `json:"Business_Loss_Type"`
	BusinessUnitsImpacted                []int         `json:"Business_Units_Impacted"`
	ConfidenceRating                     []string      `json:"Confidence_Rating"`
	ConfidentialIncident                 []interface{} `json:"Confidential_Incident"`
	ConfidentialityImpactNotes           interface{}   `json:"Confidentiality_Impact_Notes"`
	Containment                          []interface{} `json:"Containment"`
	CorporatePolicy                      []interface{} `json:"Corporate_Policy"`
	CorporatePolicyViolated              []interface{} `json:"Corporate_Policy_Violated"`
	CountOfRisks                         int           `json:"Count_of_Risks"`
	CountOfRisksIncreased                []string      `json:"Count_of_Risks_Increased"`
	CrisisEvents                         []interface{} `json:"Crisis_Events"`
	DataBreach                           []interface{} `json:"Data_Breach"`
	DataLossRating                       []interface{} `json:"Data_Loss_Rating"`
	DataRetentionEnvironment             []interface{} `json:"Data_Retention_Environment"`
	DateCreated                          time.Time     `json:"Date_Created"`
	DateTimeAssigned                     time.Time     `json:"DateTime_Assigned"`
	DateTimeClosed                       interface{}   `json:"DateTime_Closed"`
	DateTimeEscalated                    time.Time     `json:"DateTime_Escalated"`
	DateTimeEscalatedStop                interface{}   `json:"DateTime_Escalated_Stop"`
	DateTimeInProgress                   interface{}   `json:"DateTime_In_Progress"`
	DateTimeInProgressStop               interface{}   `json:"DateTime_In_Progress_Stop"`
	DateTimeModified                     time.Time     `json:"DateTime_Modified"`
	DateTimeRemediationCompleted         interface{}   `json:"DateTime_Remediation_Completed"`
	DateTimeRemediationRequested         interface{}   `json:"DateTime_Remediation_Requested"`
	DateTimeReturned                     interface{}   `json:"DateTime_Returned"`
	DaysOpen                             int           `json:"Days_Open"`
	DeclaredIncident                     []interface{} `json:"Declared_Incident"`
	DeclaredIncidentNoOfAlerts           int           `json:"Declared_Incident__No_Of_Alerts"`
	DeclaredIncidentHelper               []interface{} `json:"Declared_Incident_Helper"`
	DestinationDeviceEnterpriseManagemen []interface{} `json:"Destination_Device__Enterprise_Managemen"`
	DetectiveControlsEffective           []int         `json:"Detective_Controls_Effective"`
	DetectiveControlsIneffective         []interface{} `json:"Detective_Controls_Ineffective"`
	Eradication                          []interface{} `json:"Eradication"`
	EscalationOwner                      []interface{} `json:"Escalation_Owner"`
	EscalationStatus                     []string      `json:"Escalation_Status"`
	Findings                             []interface{} `json:"Findings"`
	GenerateIncidentResponseTasks        []string      `json:"Generate_Incident_Response_Tasks"`
	HashCode                             interface{}   `json:"hash_code"`
	HighestAlertPriority                 []interface{} `json:"Highest_Alert_Priority"`
	HostForensicAnalysis                 []interface{} `json:"Host_Forensic_Analysis"`
	IncidentConfirmation                 []string      `json:"Incident_Confirmation"`
	IncidentCoordinator                  []string      `json:"Incident_Coordinator"`
	IncidentDetails                      string        `json:"Incident_Details"`
	IncidentID                           int           `json:"Incident_ID"`
	IncidentIDDFM                        int           `json:"Incident_ID_DFM"`
	IncidentIDKPI                        string        `json:"Incident_ID_KPI"`
	IncidentJournal                      []interface{} `json:"Incident_Journal"`
	IncidentOwner                        []string      `json:"Incident_Owner"`
	IncidentQueue                        []string      `json:"Incident_Queue"`
	IncidentResponseProceduresAllLevels  []interface{} `json:"Incident_Response_Procedures__All_levels"`
	IncidentStatus                       []string      `json:"Incident_Status"`
	IncidentSummary                      string        `json:"Incident_Summary"`
	InformationAssets                    []interface{} `json:"Information_Assets"`
	InheritedRecordPermissions           []interface{} `json:"Inherited_Record_Permissions"`
	IntegrityCompromiseRating            []interface{} `json:"Integrity_Compromise_Rating"`
	IntegrityCompromised                 []interface{} `json:"Integrity_Compromised"`
	IntegrityImpactNotes                 interface{}   `json:"Integrity_Impact_Notes"`
	InvestigationControlsIneffective     []interface{} `json:"Investigation_Controls_Ineffective"`
	Investigations                       []int         `json:"Investigations"`
	InvestigativeControlsEffective       []interface{} `json:"Investigative_Controls_Effective"`
	L1QueueTimeMinutes                   int           `json:"L1_Queue_Time_Minutes"`
	L1StartTime                          interface{}   `json:"L1_Start_Time"`
	L1StopTime                           interface{}   `json:"L1_Stop_Time"`
	L2QueueTimeMinutes                   int           `json:"L2_Queue_Time_Minutes"`
	L2StartTime                          interface{}   `json:"L2_Start_Time"`
	L2StopTime                           interface{}   `json:"L2_Stop_Time"`
	LastUpdated                          time.Time     `json:"Last_Updated"`
	ManagementDefaultAccess              []string      `json:"Management_Default_Access"`
	MaturityModel                        []interface{} `json:"Maturity_Model__"`
	Members                              []interface{} `json:"Members"`
	MethodOfDiscovery                    []string      `json:"Method_of_Discovery"`
	NetWitnessRespondIncidentSource      interface{}   `json:"NetWitness_Respond_Incident_Source"`
	NetworkForensicAnalysis              []interface{} `json:"Network_Forensic_Analysis"`
	NoOfAggregatedAlerts                 int           `json:"No_of_Aggregated_Alerts"`
	NotApplicableIncidentResponseProcedu []interface{} `json:"Not_Applicable_Incident_Response_Procedu"`
	OpenTasksActivities                  []interface{} `json:"Open_TasksActivities"`
	OverallBusinessImpact                []interface{} `json:"Overall_Business_Impact"`
	OverallDataLossStatus                []string      `json:"Overall_Data_Loss_Status"`
	PolicyImpactNotes                    interface{}   `json:"Policy_Impact_Notes"`
	PolicyViolationUserEducation         []interface{} `json:"Policy_Violation__User_Education"`
	PreventiveControlsEffective          []interface{} `json:"Preventive_Controls_Effective"`
	PreventiveControlsIneffective        []interface{} `json:"Preventive_Controls_Ineffective"`
	PreviousCountOfRisks                 int           `json:"Previous_Count_of_Risks"`
	PreviousL1QueueTimeMinutes           interface{}   `json:"Previous_L1_Queue_Time__Minutes"`
	PreviousL2QueueTimeMinutes           interface{}   `json:"Previous_L2_Queue_Time__Minutes_"`
	Priority                             []string      `json:"Priority"`
	PriorityOverride                     []string      `json:"Priority_Override"`
	PriorityOverrideJustification        interface{}   `json:"Priority_Override_Justification"`
	RelatedSecurityIncidentsDirect       []interface{} `json:"Related_Security_Incidents_Direct"`
	RelatedSecurityIncidentsIndirect     []interface{} `json:"Related_Security_Incidents_Indirect"`
	RelatedThreatIntelligence            []interface{} `json:"Related_Threat_Intelligence"`
	RemediationRequired                  []interface{} `json:"Remediation_Required"`
	RequiredTasksNotImplemented          []string      `json:"Required_Tasks_Not_Implemented"`
	RiskRegisterSecurityIncidents        []interface{} `json:"Risk_Register_Security_Incidents"`
	SAIMPriority                         []interface{} `json:"SAIM_Priority"`
	SecOpsMode                           []interface{} `json:"SecOps_Mode"`
	SecurityAlerts                       []interface{} `json:"Security_Alerts"`
	ShiftHandoverIncidents               []int         `json:"Shift_Handover_Incidents"`
	ShiftHandoverOpenIncidents           []interface{} `json:"Shift_Handover_Open_Incidents"`
	SLARecalcHelperCurrentDateTime       interface{}   `json:"SLA_Recalc_Helper__Current_Date_Time"`
	SOCIRProgramImprovement              []interface{} `json:"SOCIR_Program_Improvement"`
	Source                               []string      `json:"Source"`
	SourceDeviceEnterpriseManagementCon  []interface{} `json:"Source_Device__Enterprise_Management_Con"`
	SpeakUpSecurityIncidents             []interface{} `json:"Speak_Up_Security_Incidents"`
	SpecifyRemediationAction             []interface{} `json:"Specify_Remediation_Action"`
	TargetAssetType                      []string      `json:"Target_Asset_Type"`
	TargetDetails                        []interface{} `json:"Target_Details"`
	ThreatActor                          []string      `json:"Threat_Actor"`
	ThreatCategory                       []string      `json:"Threat_Category"`
	ThreatValid                          []string      `json:"Threat_Valid"`
	ThreatVector                         []string      `json:"Threat_Vector"`
	TimeSpentEscalated                   interface{}   `json:"Time_Spent___Escalated"`
	TimeSpentInProgress                  interface{}   `json:"Time_Spent___In_Progress"`
	TimeSpentAssigned                    interface{}   `json:"Time_Spent__Assigned"`
	TimeSpentNew                         string        `json:"Time_Spent__New"`
	TimeSpentRemediation                 interface{}   `json:"Time_Spent__Remediation"`
	TimeSpentReturnedToL1                interface{}   `json:"Time_Spent__Returned_to_L1"`
	Title                                string        `json:"Title"`
	WeekCreated                          string        `json:"Week_Created"`
	WFTaskSubjectHelper                  interface{}   `json:"WF_Task_Subject_Helper"`
	WorkflowAssignees                    []interface{} `json:"Workflow_Assignees"`
	WorkflowCurrentNode                  interface{}   `json:"Workflow_Current_Node"`
	WorkflowCurrentStage                 []interface{} `json:"Workflow_Current_Stage"`
	WorkflowJobStatus                    []interface{} `json:"Workflow_Job_Status"`
	WorkflowProcessVersion               int           `json:"Workflow_Process_Version"`
	WorkflowStage                        []interface{} `json:"Workflow_Stage"`
}

// IncidentsResponse is the response.
type IncidentsResponse struct {
	OdataContext string      `json:"@odata.context"`
	Value        []*Incident `json:"value"`
}

//------------------------------------------------------------------------------
// Functions
//------------------------------------------------------------------------------

// ListIncidents returns the incidents with given cirterias.
func (endpoint *Endpoint) ListIncidents(ctx context.Context, since, until string, perPage, pageNumber int) (*IncidentsResponse, error) {
	// Authenticate and get the token
	token, err := endpoint.client.Authenticate()
	if err != nil {
		return nil, fmt.Errorf("error while authenticating : %s", err)
	}

	// Prepare the URL
	reqURL, err := url.Parse(endpoint.client.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("Error while parsing the URL : %s", err)
	}
	reqURL.Path += "/contentapi/Security_Incidents"

	// Create the request
	req, err := http.NewRequest("GET", reqURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("Error while creating the request : %s", err)
	}
	req = req.WithContext(ctx)

	// Set HTTP headers
	req.Header.Set("Authorization", fmt.Sprintf("Archer	session-id=%s", token))

	// Do the request
	resp, err := endpoint.client.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error while doing the request: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("error with the status code: %d", resp.StatusCode)
	}

	// Read the response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error while reading the request: %s", err)
	}

	// Unmarshal the response
	var incidentsResponse *IncidentsResponse
	err = json.Unmarshal([]byte(body), &incidentsResponse)
	if err != nil {
		return nil, fmt.Errorf("error while unmarshalling the response : %s", err)
	}

	return incidentsResponse, nil
}
