// PatientAccessControl.js - Core patient interface for web
import React, { useState, useEffect } from 'react';

// --- Mock Blockchain API ---
// This is a placeholder to make the app runnable.
// In a real app, you'd fetch this from a server.

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
    expiryDate: new Date(Date.now() + 10 * 24 * 60 * 60 * 1000).toISOString(), // 10 days from now
  },
  {
    permissionID: 'perm-002',
    providerName: 'Marie Curie',
    expiryDate: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString(), // 60 days from now
  },
];

const BlockchainAPI = {
  getPendingRequests: (patientID) => {
    console.log('Fetching pending requests for:', patientID);
    return new Promise((resolve) => {
      setTimeout(() => resolve(mockPending), 500);
    });
  },
  getActivePermissions: (patientID) => {
    console.log('Fetching active permissions for:', patientID);
    return new Promise((resolve) => {
      setTimeout(() => resolve(mockActive), 500);
    });
  },
  respondToAccessRequest: (requestID, approved, patientID) => {
    console.log(`Responding to ${requestID}: ${approved} for ${patientID}`);
    // Simulate removing from pending
    const index = mockPending.findIndex((req) => req.requestID === requestID);
    if (index > -1) {
      const [removed] = mockPending.splice(index, 1);
      // If approved, add to active
      if (approved) {
        mockActive.push({
          permissionID: `perm-${Math.random().toString(36).substring(7)}`,
          providerName: removed.providerName,
          expiryDate: new Date(
            Date.now() + removed.durationDays * 24 * 60 * 60 * 1000
          ).toISOString(),
        });
      }
    }
    return new Promise((resolve) => setTimeout(resolve, 300));
  },
  revokePermission: (permissionID) => {
    console.log(`Revoking ${permissionID}`);
    // Simulate removing from active
    const index = mockActive.findIndex((perm) => perm.permissionID === permissionID);
    if (index > -1) {
      mockActive.splice(index, 1);
    }
    return new Promise((resolve) => setTimeout(resolve, 300));
  },
};

// --- Helper Components ---

/**
 * Custom Modal Component
 * Replaces React Native's Alert.alert()
 */
const Modal = ({ title, message, buttons, isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm">
      <div className="bg-white w-11/12 max-w-sm mx-auto rounded-lg shadow-xl overflow-hidden">
        <div className="p-6">
          <h3 className="text-xl font-semibold text-gray-900">{title}</h3>
          <p className="text-gray-600 mt-2">{message}</p>
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

// --- Main Component ---

const PatientAccessControl = ({ patientID = 'patient-123' }) => {
  const [pendingRequests, setPendingRequests] = useState([]);
  const [activePermissions, setActivePermissions] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [modal, setModal] = useState({
    isOpen: false,
    title: '',
    message: '',
    buttons: [],
  });

  useEffect(() => {
    loadAccessRequests();
  }, []);

  const loadAccessRequests = async () => {
    setIsLoading(true);
    try {
      const [pending, active] = await Promise.all([
        BlockchainAPI.getPendingRequests(patientID),
        BlockchainAPI.getActivePermissions(patientID),
      ]);
      setPendingRequests(pending);
      setActivePermissions(active);
    } catch (error) {
      showModal('Error', error.message || 'Failed to load data.', [
        { text: 'OK', onPress: closeModal },
      ]);
    }
    setIsLoading(false);
  };

  const closeModal = () => {
    setModal({ isOpen: false, title: '', message: '', buttons: [] });
  };

  const showModal = (title, message, buttons) => {
    setModal({ isOpen: true, title, message, buttons });
  };

  const handleAccessRequest = async (requestID, approved) => {
    try {
      await BlockchainAPI.respondToAccessRequest(requestID, approved, patientID);
      showModal(
        'Success',
        approved ? 'Access granted' : 'Access denied',
        [{ text: 'OK', onPress: () => {
            closeModal();
            loadAccessRequests(); // Reload data
        }}]
      );
    } catch (error) {
      showModal('Error', error.message || 'An unknown error occurred.', [
        { text: 'OK', onPress: closeModal },
      ]);
    }
  };

  const revokeAccess = async (permissionID) => {
    showModal(
      'Revoke Access',
      'Are you sure you want to revoke this provider\'s access?',
      [
        { text: 'Cancel', style: 'cancel', onPress: closeModal },
        {
          text: 'Revoke',
          style: 'destructive',
          onPress: async () => {
            closeModal(); // Close confirmation modal
            try {
              await BlockchainAPI.revokePermission(permissionID);
              showModal('Success', 'Access has been revoked.', [
                { text: 'OK', onPress: () => {
                    closeModal();
                    loadAccessRequests(); // Reload data
                }}
              ]);
            } catch (error) {
              showModal('Error', error.message || 'Failed to revoke access.', [
                 { text: 'OK', onPress: closeModal }
              ]);
            }
          },
        },
      ]
    );
  };

  // --- Render ---

  const renderEmptyList = (message) => (
    <div className="bg-white rounded-lg shadow p-6 text-center text-gray-500">
      <p>{message}</p>
    </div>
  );

  return (
    <div className="w-full max-w-md mx-auto bg-gray-100 min-h-screen font-sans p-4">
      <Modal
        isOpen={modal.isOpen}
        title={modal.title}
        message={modal.message}
        buttons={modal.buttons}
        onClose={closeModal}
      />
      
      <h1 className="text-2xl font-bold text-center text-blue-800 mb-6">
        My Health Records
      </h1>

      {/* Pending Requests Section */}
      <section className="mb-8">
        <h2 className="text-xl font-semibold text-gray-800 mb-4">
          Pending Access Requests
        </h2>
        {isLoading ? (
          <p className="text-center text-gray-500">Loading...</p>
        ) : pendingRequests.length > 0 ? (
          <div className="space-y-4">
            {pendingRequests.map((item) => (
              <div key={item.requestID} className="bg-white rounded-lg shadow-md overflow-hidden">
                <div className="p-4">
                  <h3 className="text-lg font-semibold text-gray-900">
                    Dr. {item.providerName}
                  </h3>
                  <p className="text-sm text-gray-600 mt-1">
                    <span className="font-medium">Purpose:</span> {item.purpose}
                  </p>
                  <p className="text-sm text-gray-600 mt-1">
                    <span className="font-medium">Duration:</span> {item.durationDays} days
                  </p>
                </div>
                <div className="bg-gray-50 px-4 py-3 flex gap-3">
                  <button
                    onClick={() => handleAccessRequest(item.requestID, true)}
                    className="flex-1 bg-blue-600 text-white px-4 py-2 rounded-md font-semibold text-sm transition-colors hover:bg-blue-700"
                  >
                    Approve
                  </button>
                  <button
                    onClick={() => handleAccessRequest(item.requestID, false)}
                    className="flex-1 bg-gray-200 text-gray-800 px-4 py-2 rounded-md font-semibold text-sm transition-colors hover:bg-gray-300"
                  >
                    Deny
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          renderEmptyList('No pending requests')
        )}
      </section>

      {/* Active Permissions Section */}
      <section>
        <h2 className="text-xl font-semibold text-gray-800 mb-4">
          Active Permissions
        </h2>
        {isLoading ? (
          <p className="text-center text-gray-500">Loading...</p>
        ) : activePermissions.length > 0 ? (
          <div className="space-y-4">
            {activePermissions.map((item) => (
              <div key={item.permissionID} className="bg-white rounded-lg shadow-md overflow-hidden">
                <div className="p-4">
                  <h3 className="text-lg font-semibold text-gray-900">
                    Dr. {item.providerName}
                  </h3>
                  <p className="text-sm text-gray-600 mt-1">
                    Expires: {new Date(item.expiryDate).toLocaleDateString()}
                  </p>
                </div>
                <div className="bg-gray-50 px-4 py-3">
                  <button
                    onClick={() => revokeAccess(item.permissionID)}
                    className="w-full bg-red-600 text-white px-4 py-2 rounded-md font-semibold text-sm transition-colors hover:bg-red-700"
                  >
                    Revoke Access
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          renderEmptyList('No active permissions')
        )}
      </section>
    </div>
  );
};

export default PatientAccessControl;

