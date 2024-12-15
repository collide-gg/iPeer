const express = require('express');
const router = express.Router();
const { createAppointment, getAppointmentsClient, getAppointmentsPeer } = require('../models/appointment');
const { db } = require('../firebaseAdmin');
const { sendAppointmentConfirmation } = require('../services/emailService');

const checkPeerCounselorAvailability = async (peerCounselorId, date, time) => {
  try {
    const appointmentsRef = db.collection('appointments');
    const existingAppointments = await appointmentsRef
      .where('peerCounselorId', '==', peerCounselorId)
      .where('date', '==', date)
      .where('time', '==', time)
      .get();

    return existingAppointments.empty;
  } catch (error) {
    console.error('Error checking availability:', error);
    throw error;
  }
};

// Route to create an appointment
router.post('/create-appointment', async (req, res) => {
  const appointmentData = {
    ...req.body,
    status: 'pending'
  };
  
  try {
    const isAvailable = await checkPeerCounselorAvailability(
      appointmentData.peerCounselorId,
      appointmentData.date,
      appointmentData.time
    );

    if (!isAvailable) {
      return res.status(409).send({ 
        error: 'Peer counselor is not available at the selected date and time' 
      });
    }

    const { appointmentId, roomId } = await createAppointment(appointmentData);
    
    const clientDoc = await db.collection('users').doc(appointmentData.clientId).get();
    const counselorDoc = await db.collection('users').doc(appointmentData.peerCounselorId).get();
    
    await sendAppointmentConfirmation(
      clientDoc.data().email,
      counselorDoc.data().email,
      {
        date: appointmentData.date,
        time: appointmentData.time,
        clientName: clientDoc.data().displayName,
        peerCounselorName: counselorDoc.data().displayName,
        roomLink: `http://localhost:5173/counseling/${roomId}`
      }
    );

    res.status(201).send({ appointmentId, roomId });
  } catch (error) {
    console.error('Error creating appointment:', error);
    res.status(500).send({ error: 'Error creating appointment' });
  }
});

// Route to check availability
router.get('/check-availability/:peerCounselorId', async (req, res) => {
  const { peerCounselorId } = req.params;
  const { date, time } = req.query;

  try {
    const isAvailable = await checkPeerCounselorAvailability(peerCounselorId, date, time);
    res.status(200).json({ available: isAvailable });
  } catch (error) {
    console.error('Error checking availability:', error);
    res.status(500).json({ error: 'Error checking availability' });
  }
});

// Route to get client appointments
router.get('/appointments/client/:clientId', async (req, res) => {
  const { clientId } = req.params;
  try {
    const appointments = await getAppointmentsClient(clientId);
    res.status(200).send(appointments);
  } catch (error) {
    console.error('Error fetching appointments:', error);
    res.status(500).send({ error: 'Error fetching appointments' });
  }
});

// Route to get peer counselor appointments
router.get('/appointments/peer-counselor/:peerCounselorId', async (req, res) => {
  const { peerCounselorId } = req.params;
  try {
    const appointments = await getAppointmentsPeer(peerCounselorId);
    res.status(200).send(appointments);
  } catch (error) {
    console.error('Error fetching appointments:', error);
    res.status(500).send({ error: 'Error fetching appointments' });
  }
});

// Route to update appointment status
router.put('/appointments/:appointmentId/status', async (req, res) => {
  const { appointmentId } = req.params;
  const { status } = req.body;

  try {
    const appointmentRef = db.collection('appointments').doc(appointmentId);
    await appointmentRef.update({ status });

    // Send immediate response
    res.status(200).send({ message: 'Appointment status updated successfully' });

    // Handle email sending in background
    if (status === 'accepted') {
      const updatedAppointment = await appointmentRef.get();
      const appointmentData = updatedAppointment.data();

      Promise.all([
        db.collection('users').doc(appointmentData.clientId).get(),
        db.collection('users').doc(appointmentData.peerCounselorId).get()
      ]).then(([clientDoc, counselorDoc]) => {
        sendAppointmentConfirmation(
          clientDoc.data().email,
          counselorDoc.data().email,
          {
            date: appointmentData.date,
            time: appointmentData.time,
            clientName: clientDoc.data().displayName,
            peerCounselorName: counselorDoc.data().displayName,
            roomLink: `http://localhost:5173/counseling/${appointmentData.roomId}`
          }
        ).catch(error => console.error('Error sending email:', error));
      }).catch(error => console.error('Error fetching user data:', error));
    }
  } catch (error) {
    console.error('Error updating appointment status:', error);
    res.status(500).send({ error: 'Error updating appointment status' });
  }
});

module.exports = router;
