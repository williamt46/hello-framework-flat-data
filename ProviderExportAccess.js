import React, { useState } from 'react';

// --- Mock Blockchain API ---
// This is a placeholder to make the app runnable.
// It includes mock data and functions for BOTH the patient and provider portals.

const mockPending = [
  {
    requestID: 'req-001',
    providerName: 'Ada Lovelace',
    purpose: 'Routine Checkup Follow-up',
    durationDays: 30,
  },
  {
    requestID: 'req-002',
    providerName: 'Grace Hopper',
    purpose: 'Specialist Consultation',
    durationDays: 7,
  },
];

const mockActive = [
  {
    permissionID: 'perm-001',
    providerName: 'Alan Turing',
    patientID: 'patient-123', // Added for better mocking
    expiryDate: new Date(Date.now() + 10 * 24 * 60 * 60 * 1000).toISOString(), // 10 days from now
  },
  {
    permissionID: 'perm-002',
    providerName: 'Marie Curie',
    patientID: 'patient-456', // Added for better mocking
    expiryDate: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString(), // 60 days from now
  },
];

const mockPatientRecords = {
  "patient-123": {
    patientInfo: { id: "patient-123", name: "Alex Johnson", dob: "1985-04-12" },
    allergies: ["Peanuts", "Penicillin"],
    medications: [{ name: "Lisinopril", dosage: "10mg" }],
    recentVisits: [{ date: "2025-10-01", reason: "Annual Checkup", provider: "Dr. Ada Lovelace" }]
  },
  "patient-456": {
     patientInfo: { id: "patient-456", name: "Maria Garcia", dob: "1992-11-30" },
     allergies: ["None"],
     medications: [],
     recentVisits: [{ date: "2025-09-15", reason: "Flu Shot", provider: "Dr. Marie Curie" }]
  }
};

const BlockchainAPI = {
  // --- Patient Portal Functions ---
  getPendingRequests: (patientID) => {
    console.log('Fetching pending requests for:', patientID);
    return new Promise((resolve) => {
      setTimeout(() => resolve(mockPending), 500);
    });
  },
  getActivePermissions: (patientID) => {
    console.log('Fetching active permissions for:', patientID);
    return new Promise((resolve) => {
      setTimeout(() => resolve(mockActive.filter(p => p.patientID === patientID)), 500);
    });
  },
  respondToAccessRequest: (requestID, approved, patientID) => {
    console.log(`Responding to ${requestID}: ${approved} for ${patientID}`);
    const index = mockPending.findIndex((req) => req.requestID === requestID);
    if (index > -1) {
      const [removed] = mockPending.splice(index, 1);
      if (approved) {
        mockActive.push({
          permissionID: `perm-${Math.random().toString(36).substring(7)}`,
          providerName: removed.providerName,
          patientID: patientID,
          expiryDate: new Date(Date.now() + removed.durationDays * 24 * 60 * 60 * 1000).toISOString(),
        });
      }
    }
    return new Promise((resolve) => setTimeout(resolve, 300));
  },
  revokePermission: (permissionID) => {
    console.log(`Revoking ${permissionID}`);
    const index = mockActive.findIndex((perm) => perm.permissionID === permissionID);
    if (index > -1) {
      mockActive.splice(index, 1);
    }
    return new Promise((resolve) => setTimeout(resolve, 300));
  },

  // --- Provider Portal Functions ---
  requestAccess: ({ providerID, patientID, purpose, durationDays = 30 }) => {
    console.log('Requesting access for:', { providerID, patientID, purpose, durationDays });
    const requestID = `req-${Math.random().toString(36).substring(7)}`;
    const providerName = providerID === 'provider-789' ? 'Dr. House' : 'Default Provider';
    
    // Add to pending for the patient to approve
    mockPending.push({
        requestID,
        providerName: providerName,
        purpose,
        durationDays
    });
    
    return new Promise((resolve) => {
      setTimeout(() => resolve(requestID), 500);
    });
  },
  verifyAccess: (providerID, patientID) => {
    console.log('Verifying access for:', providerID, patientID);
    const hasPermission = mockActive.some(
      p => p.patientID === patientID && new Date(p.expiryDate) > new Date()
      // In a real app, you'd also verify p.providerID === providerID
    );
    return new Promise((resolve) => {
        setTimeout(() => resolve(hasPermission), 400);
    });
  },
  getPatientRecords: (patientID) => {
     console.log('Fetching records for patient:', patientID);
     return new Promise((resolve, reject) => {
        setTimeout(() => {
            const records = mockPatientRecords[patientID];
            if (records) {
                resolve(records);
            } else {
                reject(new Error("No records found for this patient ID."));
            }
        }, 800);
     });
  }
};

// --- Helper Components ---

/**
 * Custom Modal Component
 * Replaces window.alert()
 */
const Modal = ({ title, message, buttons, isOpen }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm">
      <div className="bg-white w-11/12 max-w-sm mx-auto rounded-lg shadow-xl overflow-hidden">
        <div className="p-6">
          <h3 className="text-xl font-semibold text-gray-900">{title}</h3>
          <p className="text-gray-600 mt-2 whitespace-pre-wrap">{message}</p>
        </div>
        <div className="bg-gray-50 px-6 py-3 flex flex-col sm:flex-row-reverse gap-2">
          {buttons.map((btn, index) => (
            <button
              key={index}
              onClick={btn.onPress}
              className={`w-full rounded-md px-4 py-2 text-sm font-medium transition-colors ${
                btn.style === 'destructive'
                  ? 'bg-red-600 text-white hover:bg-red-700'
                  : btn.style === 'cancel'
                  ? 'bg-gray-200 text-gray-800 hover:bg-gray-300'
                  : 'bg-blue-600 text-white hover:bg-blue-700'
              }`}
            >
              {btn.text}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};

/**
 * Mock RecordViewer Component
 */
const RecordViewer = ({ records, patientID, providerID }) => {
  // Destructure records for easier access
  const { patientInfo, allergies, medications, recentVisits } = records;

  // Helper to render list items
  const renderListItem = (item, index) => (
    <li key={index} className="py-2 px-3 bg-white hover:bg-gray-50 rounded-md text-sm">
      {item}
    </li>
  );

  return (
    <div className="mt-6 p-4 bg-gray-50 rounded-lg shadow-inner border border-gray-200">
      <h3 className="text-lg font-semibold text-gray-800">
        Viewing Records for Patient: {patientInfo.name} ({patientID})
      </h3>
      <p className="text-sm text-gray-600 mb-4">
        Accessed by: {providerID}
      </p>

      {/* Patient Info Section */}
      <div className="mb-4">
        <h4 className="text-md font-semibold text-gray-700 mb-2 border-b pb-1">Patient Information</h4>
        <div className="bg-white p-3 rounded-md shadow-sm">
          <p className="text-sm"><span className="font-medium text-gray-600">Name:</span> {patientInfo.name}</p>
          <p className="text-sm"><span className="font-medium text-gray-600">Date of Birth:</span> {patientInfo.dob}</p>
        </div>
      </div>

      {/* Allergies Section */}
      <div className="mb-4">
        <h4 className="text-md font-semibold text-gray-700 mb-2 border-b pb-1">Allergies</h4>
        <ul className="space-y-1 bg-gray-100 p-2 rounded-md">
          {allergies.length > 0 ? (
            allergies.map(renderListItem)
          ) : (
            <li className="py-2 px-3 bg-white text-gray-500 rounded-md text-sm">No known allergies.</li>
          )}
        </ul>
      </div>

      {/* Medications Section */}
      <div className="mb-4">
        <h4 className="text-md font-semibold text-gray-700 mb-2 border-b pb-1">Medications</h4>
        <ul className="space-y-2">
          {medications.length > 0 ? (
            medications.map((med, index) => (
              <li key={index} className="p-3 bg-white rounded-md shadow-sm">
                <p className="text-sm font-semibold text-blue-700">{med.name}</p>
                <p className="text-sm text-gray-600">Dosage: {med.dosage}</p>
              </li>
            ))
          ) : (
            <li className="p-3 bg-white text-gray-500 rounded-md shadow-sm text-sm">No active medications.</li>
          )}
        </ul>
      </div>

      {/* Recent Visits Section */}
      <div>
        <h4 className="text-md font-semibold text-gray-700 mb-2 border-b pb-1">Recent Visits</h4>
        <ul className="space-y-2">
          {recentVisits.length > 0 ? (
            recentVisits.map((visit, index) => (
              <li key={index} className="p-3 bg-white rounded-md shadow-sm border-l-4 border-blue-500">
                <p className="text-sm font-semibold text-gray-800">{visit.reason}</p>
                <p className="text-sm text-gray-600">Date: {visit.date}</p>
                <p className="text-sm text-gray-600">Provider: {visit.provider}</p>
              </li>
            ))
          ) : (
            <li className="p-3 bg-white text-gray-500 rounded-md shadow-sm text-sm">No recent visits.</li>
          )}
        </ul>
      </div>
    </div>
  );
};


// --- Main Component ---

// Renamed to 'App' to be the default export
export default function App({ providerID = 'provider-789' }) {
    const [patientID, setPatientID] = useState('patient-123'); // Pre-filled for demo
    const [accessPurpose, setAccessPurpose] = useState('consultation'); // Pre-filled for demo
    const [records, setRecords] = useState(null);
    const [loading, setLoading] = useState(false);
    
    // Modal state
    const [modal, setModal] = useState({
      isOpen: false,
      title: '',
      message: '',
      buttons: [],
    });

    // Modal helper functions
    const closeModal = () => {
      setModal({ isOpen: false, title: '', message: '', buttons: [] });
    };

    const showModal = (title, message, buttons) => {
      setModal({ isOpen: true, title, message, buttons });
    };
    
    const requestAccess = async (e) => {
        e.preventDefault();
        setLoading(true);
        setRecords(null); // Clear previous records
        
        try {
            // Request access on blockchain
            const requestID = await BlockchainAPI.requestAccess({
                providerID,
                patientID,
                purpose: accessPurpose,
                durationDays: 30 // Default 30-day access
            });
            
            showModal(
              'Request Submitted',
              `Access request submitted. Request ID: ${requestID}\n\nThe patient will be notified to approve/deny.`,
              [{ text: 'OK', onPress: closeModal }]
            );
        } catch (error) {
            showModal('Error', error.message, [{ text: 'OK', onPress: closeModal }]);
        } finally {
            setLoading(false);
        }
    };
    
    const viewRecords = async () => {
        setLoading(true);
        setRecords(null); // Clear previous records
        
        try {
            // Verify access on blockchain
            const hasAccess = await BlockchainAPI.verifyAccess(
                providerID,
                patientID
            );
            
            if (!hasAccess) {
                showModal(
                  'Access Denied',
                  'You do not have active access to this patient\'s records. Please request access first.',
                  [{ text: 'OK', onPress: closeModal }]
                );
                return;
            }
            
            // Retrieve records
            const patientRecords = await BlockchainAPI.getPatientRecords(patientID);
            setRecords(patientRecords);
        } catch (error) {
            showModal('Error', error.message, [{ text: 'OK', onPress: closeModal }]);
        } finally {
            setLoading(false);
        }
    };
    
    return (
        <div className="w-full max-w-md mx-auto bg-gray-100 min-h-screen font-sans p-4">
            <Modal
              isOpen={modal.isOpen}
              title={modal.title}
              message={modal.message}
              buttons={modal.buttons}
            />

            <h1 className="text-2xl font-bold text-center text-blue-800 mb-6">
              Provider Portal
            </h1>
            
            {/* --- Request Access Form --- */}
            <form onSubmit={requestAccess} className="bg-white rounded-lg shadow-md p-6 space-y-4 mb-6">
                <h2 className="text-xl font-semibold text-gray-800 mb-4">
                  Request Patient Access
                </h2>
                <div>
                    <label htmlFor="patientID" className="block text-sm font-medium text-gray-700">
                      Patient ID:
                    </label>
                    <input
                        id="patientID"
                        type="text"
                        value={patientID}
                        onChange={(e) => setPatientID(e.target.value)}
                        placeholder="Enter patient ID"
                        required
                        className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                    />
                </div>
                
                <div>
                    <label htmlFor="purpose" className="block text-sm font-medium text-gray-700">
                      Purpose of Access:
                    </label>
                    <select
                        id="purpose"
                        value={accessPurpose}
                        onChange={(e) => setAccessPurpose(e.target.value)}
                        required
                        className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
                    >
                        <option value="">Select purpose...</option>
                        <option value="treatment">Treatment</option>
                        <option value="consultation">Consultation</option>
                        <option value="emergency">Emergency Care</option>
                        <option value="followup">Follow-up</option>
                    </select>
                </div>
                
                <button 
                  type="submit" 
                  disabled={loading}
                  className="w-full bg-blue-600 text-white px-4 py-2 rounded-md font-semibold text-sm transition-colors hover:bg-blue-700 disabled:bg-blue-300"
                >
                    {loading ? 'Requesting...' : 'Request Access'}
                </button>
            </form>
            
            {/* --- View Records Section --- */}
            <div className="bg-white rounded-lg shadow-md p-6">
                <h2 className="text-xl font-semibold text-gray-800 mb-4">
                  View Patient Records
                </h2>
                <button 
                  onClick={viewRecords} 
                  disabled={loading || !patientID}
                  className="w-full bg-green-600 text-white px-4 py-2 rounded-md font-semibold text-sm transition-colors hover:bg-green-700 disabled:bg-green-300"
                >
                    {loading ? 'Loading...' : 'View Records for Patient'}
                </button>
                
                {records && (
                    <RecordViewer 
                        records={records}
                        patientID={patientID}
                        providerID={providerID}
                    />
                )}
            </div>
        </div>
    );
};

