import React from 'react';

const PendingAppointments = ({ appointments, clients, peerCounselors, handleAppointmentStatus, role }) => {
  const now = new Date();
  const today = now.toISOString().split('T')[0];
  const currentTime = now.toLocaleTimeString('en-US', { 
      hour12: false, 
      hour: '2-digit', 
      minute: '2-digit',
      hourCycle: 'h23' 
  });

  // Convert appointment time to 24-hour format for comparison
  const formatTo24Hour = (time) => {
      const [hours, minutes] = time.split(':');
      return `${hours.padStart(2, '0')}:${minutes}`;
  };

  const pendingAppointments = appointments.filter(apt => {
      console.log('Comparing times:', {
          current: currentTime,
          appointment: formatTo24Hour(apt.time)
      });
      
      if (apt.status !== 'pending') return false;
      
      if (apt.date > today) return true;
      
      if (apt.date === today) {
          return formatTo24Hour(apt.time) > currentTime;
      }
      
      return false;
  });

  const getUserName = (appointment) => {
    if (role === 'client') {
      return peerCounselors[appointment.peerCounselorId] || 'Loading...';
    }
    return clients[appointment.clientId] || 'Loading...';
  };

  const getUserLabel = () => {
    return role === 'client' ? 'Peer Counselor' : 'Client';
  };

  return (
    <div className="space-y-4">
      {pendingAppointments.length === 0 ? (
        <div className="text-center py-8 bg-white rounded-lg shadow-sm">
          <p className="text-gray-600">No pending appointments</p>
        </div>
      ) : (
        pendingAppointments.map((appointment) => (
          <div 
            key={appointment.id} 
            className="bg-white rounded-lg shadow-sm hover:shadow-md transition-shadow duration-200 p-6"
          >
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <div className="flex items-center">
                  <svg className="h-5 w-5 text-indigo-500 mr-2" fill="none" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" viewBox="0 0 24 24" stroke="currentColor">
                    <path d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                  </svg>
                  <span className="text-gray-700 font-medium">{appointment.date}</span>
                </div>
                <div className="flex items-center">
                  <svg className="h-5 w-5 text-indigo-500 mr-2" fill="none" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" viewBox="0 0 24 24" stroke="currentColor">
                    <path d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <span className="text-gray-700 font-medium">{appointment.time}</span>
                </div>
              </div>
              
              <div className="space-y-2">
                <div className="flex items-center">
                  <svg className="h-5 w-5 text-indigo-500 mr-2" fill="none" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" viewBox="0 0 24 24" stroke="currentColor">
                    <path d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                  </svg>
                  <span className="text-gray-700">
                    {getUserLabel()}: {getUserName(appointment)}
                  </span>
                </div>
              </div>
            </div>

            <div className="mt-4">
              <p className="text-gray-600">
                <span className="font-medium">Description: </span>
                {appointment.description}
              </p>
            </div>

            <div className="mt-4">
                <p className={`text-sm font-medium mb-2 ${
                  appointment.status === 'accepted' ? 'text-green-600' : 
                  appointment.status === 'declined' ? 'text-red-600' : 
                  'text-yellow-600'
                }`}>
                  Status: {appointment.status ? appointment.status.charAt(0).toUpperCase() + appointment.status.slice(1) : 'Pending'}
                </p>
                {role === 'client' && appointment.status === 'pending' && (
                  <p className="text-xs text-gray-500">
                    Thanks for your patience! Your request is under review. 😊
                  </p>
                )}
            </div>

            {role === 'peer-counselor' && handleAppointmentStatus && (
              <div className="mt-4 flex gap-2">
                <button
                  onClick={() => handleAppointmentStatus(appointment.id, 'accepted')}
                  className="bg-green-500 text-white px-6 py-2 rounded-lg hover:bg-green-600 transition-colors"
                >
                  Accept
                </button>
                <button
                  onClick={() => handleAppointmentStatus(appointment.id, 'declined')}
                  className="bg-red-500 text-white px-6 py-2 rounded-lg hover:bg-red-600 transition-colors"
                >
                  Decline
                </button>
              </div>
            )}
          </div>
        ))
      )}
    </div>
  );
};

export default PendingAppointments;