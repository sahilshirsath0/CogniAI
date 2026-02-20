export const AdminAnalysisPage = (user, events = [], selectedEventStats = null) => {
   const now = new Date();
   const liveEvents = events.filter(e => new Date(e.registrationDeadline) >= now);
   const expiredEvents = events.filter(e => new Date(e.registrationDeadline) < now);

   // Helper for Pie Chart (CSS Conic Gradient)
   const generatePieChart = (stats) => {
      const entries = Object.entries(stats);
      if (entries.length === 0) return '<div style="text-align: center; color: #64748B;">No department data</div>';

      let currentTotal = 0;
      const total = entries.reduce((acc, [_, val]) => acc + val, 0);

      const gradients = entries.map(([dept, val], index) => {
         const start = (currentTotal / total) * 100;
         currentTotal += val;
         const end = (currentTotal / total) * 100;
         const colors = ['#2563EB', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#EC4899', '#06B6D4'];
         const color = colors[index % colors.length];
         return `${color} ${start}% ${end}%`;
      }).join(', ');

      return `
      <div style="display: flex; align-items: center; gap: 2rem; flex-wrap: wrap;">
        <div style="width: 200px; height: 200px; border-radius: 50%; background: conic-gradient(${gradients}); box-shadow: 0 4px 6px rgba(0,0,0,0.1); position: relative;">
          <div style="position: absolute; top: 20%; left: 20%; right: 20%; bottom: 20%; background: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-direction: column;">
             <span style="font-size: 1.5rem; font-weight: 800; color: #1E293B;">${total}</span>
             <span style="font-size: 0.6rem; color: #64748B; font-weight: 700;">TOTAL</span>
          </div>
        </div>
        <div style="display: grid; gap: 0.5rem;">
           ${entries.map(([dept, val], index) => {
         const colors = ['#2563EB', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#EC4899', '#06B6D4'];
         return `
               <div style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.8rem;">
                  <div style="width: 10px; height: 10px; border-radius: 2px; background: ${colors[index % colors.length]}"></div>
                  <span style="font-weight: 700; color: #1E293B;">${dept}:</span>
                  <span style="color: #64748B;">${val}</span>
               </div>
             `;
      }).join('')}
        </div>
      </div>
    `;
   };

   const renderEventCard = (e, statusLabel, statusColor) => `
    <div class="dashboard-reveal" style="background: white; border-radius: 16px; border: 1px solid var(--border); overflow: hidden; cursor: pointer; transition: all 0.3s; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);" 
         onclick="window.app.fetchEventAnalysis('${e._id}')">
       <div style="height: 140px; position: relative;">
          <img src="${e.image || 'https://images.unsplash.com/photo-1591115765373-5207764f72e7?q=80&w=1000&auto=format&fit=crop'}" style="width: 100%; height: 100%; object-fit: cover;">
          <div style="position: absolute; top: 0.8rem; right: 0.8rem; background: ${statusColor}; color: white; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.65rem; font-weight: 800; text-transform: uppercase;">${statusLabel}</div>
       </div>
       <div style="padding: 1.2rem;">
          <h3 style="font-size: 1.1rem; font-weight: 800; color: #1E293B; margin-bottom: 0.4rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${e.title}</h3>
          <div style="font-size: 0.8rem; color: #64748B;">${e.type} • ${e.department}</div>
          <div style="margin-top: 1rem; color: var(--primary); font-weight: 800; font-size: 0.85rem;">View Analysis →</div>
       </div>
    </div>
  `;

   return `
    <div class="dashboard-container" style="background: #F8FAFC; min-height: 100vh;">
      <nav style="background: white; border-bottom: 1px solid var(--border); padding: 1rem 5%; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 100;">
        <div class="logo" style="cursor: pointer; color: var(--primary); font-weight: 800; display: flex; align-items: center; gap: 0.8rem;" onclick="window.app.navigate('dashboard')">
           <div style="width: 32px; height: 32px; background: var(--primary); border-radius: 8px; display: flex; align-items: center; justify-content: center; color: white;">←</div>
           <span>COGNI INTELLIGENCE</span>
        </div>
        <div style="display: flex; gap: 1.5rem; align-items: center;">
           <span style="font-size: 0.85rem; color: #64748B; font-weight: 700; background: #F1F5F9; padding: 0.4rem 1rem; border-radius: 50px;">System Administrator: ${user.name}</span>
           <button class="btn btn-primary" style="padding: 0.4rem 1rem; font-size: 0.75rem; border-radius: 50px; background: #EF4444; border: none;" onclick="window.app.logout()">Sign Out</button>
        </div>
      </nav>

      <div class="container" style="padding: 3rem 5%;">
        
        ${!selectedEventStats ? `
           <!-- Selection Screen (Available & Expired) -->
           <section style="margin-bottom: 4rem;">
              <h2 style="margin-bottom: 1.5rem; display: flex; align-items: center; gap: 0.8rem; font-weight: 800; color: #1E293B;">
                 <span style="color: #10B981;">●</span> Live & Upcoming Events
              </h2>
              <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 2rem;">
                 ${liveEvents.length > 0 ? liveEvents.map(e => renderEventCard(e, 'Live', '#10B981')).join('') : '<p style="color: #64748B;">No live events found.</p>'}
              </div>
           </section>

           <section style="margin-top: 5rem;">
              <h2 style="margin-bottom: 1.5rem; display: flex; align-items: center; gap: 0.8rem; font-weight: 800; color: #1E293B;">
                 <span style="color: #EF4444;">●</span> Expired / Past Events
              </h2>
              <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 2rem;">
                 ${expiredEvents.length > 0 ? expiredEvents.map(e => renderEventCard(e, 'Expired', '#64748B')).join('') : '<p style="color: #64748B;">No past events found.</p>'}
              </div>
           </section>
        ` : `
           <!-- Deep Dive View -->
           <button class="btn btn-outline" style="margin-bottom: 2.5rem; background: white;" onclick="window.app.renderAnalysisScreen()">← Back to Selection</button>
           
           <div style="background: white; border-radius: 24px; padding: 2.5rem; border: 1px solid var(--border); box-shadow: 0 4px 6px rgba(0,0,0,0.05);">
              
              <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 3rem; border-bottom: 1px solid #F1F5F9; padding-bottom: 2rem;">
                 <div>
                    <h1 style="font-size: 2.5rem; font-weight: 800; color: #1E293B; line-height: 1.2;">${selectedEventStats.title}</h1>
                    <div style="margin-top: 0.5rem; color: #64748B; font-weight: 600;">Overall Data & Registration Monitoring</div>
                 </div>
                 <div style="display: flex; gap: 1rem; align-items: center; flex-wrap: wrap;">
                    <div style="display: flex; gap: 0.5rem;">
                       <button class="btn btn-outline" style="padding: 0.6rem 1rem; font-size: 0.8rem; border-radius: 8px;" onclick="window.app.openEditPostModal('${selectedEventStats.eventId}')">
                          ✏️ Edit
                       </button>
                       <button class="btn btn-outline" style="padding: 0.6rem 1rem; font-size: 0.8rem; border-radius: 8px; border-color: #EF4444; color: #EF4444;" onclick="window.app.deleteEvent('${selectedEventStats.eventId}')">
                          🗑️ Delete
                       </button>
                    </div>
                    <div style="width: 1px; height: 30px; background: #E2E8F0;"></div>
                    <button class="btn btn-outline" style="padding: 0.8rem 1.5rem; border-radius: 12px; border: 1px solid #10B981; color: #10B981; font-weight: 700;" onclick="window.app.openCertificateModal('${selectedEventStats.eventId}')">
                       🎓 Release Certificates
                    </button>
                    <button class="btn btn-primary" style="padding: 0.8rem 1.5rem; border-radius: 12px;" onclick="window.location.href='https://cogniai-1xcj.onrender.com/api/admin/export/registrations?eventId=${selectedEventStats.eventId}'">
                       📥 Download CSV Report
                    </button>
                 </div>
              </div>

              <!-- Top Row: Stats & Pie Chart -->
              <div style="display: grid; grid-template-columns: 1fr 400px; gap: 3rem; margin-bottom: 4rem;">
                 <div>
                    <h3 style="font-size: 1.1rem; font-weight: 800; color: #1E293B; margin-bottom: 1.5rem;">Department Breakdown</h3>
                    <div style="background: #F8FAFC; padding: 2rem; border-radius: 20px; border: 1px solid #E2E8F0;">
                       ${generatePieChart(selectedEventStats.deptStats || {})}
                    </div>
                 </div>
                 <div style="display: grid; gap: 1.5rem;">
                    <div style="background: #F0F9FF; padding: 1.5rem; border-radius: 16px; border: 1px solid #BAE6FD;">
                       <div style="font-size: 0.75rem; color: #0369A1; font-weight: 800; text-transform: uppercase;">Total Registrations</div>
                       <div style="font-size: 2.2rem; font-weight: 800; color: #0C4A6E; margin-top: 0.4rem;">${selectedEventStats.totalRegistrations}</div>
                    </div>
                    <div style="background: #F0FDF4; padding: 1.5rem; border-radius: 16px; border: 1px solid #BBF7D0;">
                       <div style="font-size: 0.75rem; color: #166534; font-weight: 800; text-transform: uppercase;">Confirmed Entries</div>
                       <div style="font-size: 2.2rem; font-weight: 800; color: #064E3B; margin-top: 0.4rem;">${selectedEventStats.confirmedCount}</div>
                    </div>
                 </div>
              </div>

              <!-- Registration List (The requested "who was register" part) -->
              <div style="margin-top: 4rem;">
                 <h3 style="font-size: 1.1rem; font-weight: 800; color: #1E293B; margin-bottom: 1.5rem; display: flex; justify-content: space-between; align-items: center;">
                    Detailed Registration List
                    <span style="font-size: 0.8rem; font-weight: 600; color: #64748B;">Showing ${selectedEventStats.registrations?.length || 0} participants</span>
                 </h3>
                 <div style="overflow-x: auto; background: #F8FAFC; border-radius: 16px; border: 1px solid #E2E8F0;">
                    <table style="width: 100%; border-collapse: collapse; font-size: 0.85rem;">
                       <thead>
                          <tr style="background: #F1F5F9; text-align: left;">
                             <th style="padding: 1rem; color: #475569; font-weight: 800;">Student Name</th>
                             <th style="padding: 1rem; color: #475569; font-weight: 800;">Department</th>
                             <th style="padding: 1rem; color: #475569; font-weight: 800;">Year</th>
                             <th style="padding: 1rem; color: #475569; font-weight: 800;">Account</th>
                             <th style="padding: 1rem; color: #475569; font-weight: 800;">Type</th>
                             <th style="padding: 1rem; color: #475569; font-weight: 800;">Status</th>
                          </tr>
                       </thead>
                       <tbody>
                          ${(selectedEventStats.registrations || []).length > 0 ? selectedEventStats.registrations.map(reg => `
                             <tr style="border-bottom: 1px solid #E2E8F0;">
                                <td style="padding: 1rem; font-weight: 700; color: #1E293B;">${reg.studentName}</td>
                                <td style="padding: 1rem; color: #64748B;">${reg.dept}</td>
                                <td style="padding: 1rem; color: #64748B;">${reg.year}</td>
                                <td style="padding: 1rem;">
                                   <div style="display: flex; align-items: center; gap: 0.4rem; font-size: 0.7rem; font-weight: 800; color: ${reg.isVerified ? '#10B981' : '#94A3B8'};">
                                      <span style="width: 6px; height: 6px; border-radius: 50%; background: currentColor;"></span>
                                      ${reg.isVerified ? 'VERIFIED' : 'UNVERIFIED'}
                                   </div>
                                </td>
                                <td style="padding: 1rem; color: #64748B;">${reg.type} ${reg.teamName ? `(${reg.teamName})` : ''}</td>
                                <td style="padding: 1rem;">
                                   <span style="padding: 0.2rem 0.6rem; border-radius: 50px; font-size: 0.7rem; font-weight: 800; background: ${reg.isConfirmed ? '#DCFCE7' : '#FEF3C7'}; color: ${reg.isConfirmed ? '#166534' : '#92400E'};">
                                      ${reg.isConfirmed ? 'CONFIRMED' : 'PENDING'}
                                   </span>
                                </td>
                             </tr>
                          `).join('') : '<tr><td colspan="6" style="padding: 3rem; text-align: center; color: #64748B;">No registrations found for this event.</td></tr>'}
                       </tbody>
                    </table>
                 </div>
              </div>

           </div>
        `}
      </div>
      <div id="certificateModal" class="modal-overlay">
        <div class="modal-content">
           <button class="modal-close" onclick="window.app.closeCertificateModal()">&times;</button>
           <h2 style="margin-bottom: 1rem; color: #1E293B;">Release Certificates</h2>
           <p style="color: #64748B; margin-bottom: 2rem;">Upload the certificate template. The system will automatically overlay student names and send emails to all confirmed participants.</p>
           
           <form onsubmit="window.app.handleReleaseCertificates(event)">
              <input type="hidden" name="eventId" id="certEventId">
              <div class="form-group">
                 <label>Certificate Template (Image)</label>
                 <input type="file" name="template" accept="image/*" required style="border: 2px dashed #E2E8F0; padding: 2rem; border-radius: 12px; width: 100%; text-align: center;">
                 <p style="font-size: 0.8rem; color: #94A3B8; margin-top: 0.5rem;">Recommended Size: 2000x1400px (Landscape)</p>
              </div>

              <button type="submit" class="btn btn-primary" style="width: 100%; padding: 1rem; margin-top: 2rem;">🚀 Generate & Send Certificates</button>
           </form>
        </div>
      </div>

      <!-- Edit Event Modal -->
       <div id="editPostModal" class="modal-overlay">
        <div class="modal-content" style="border-radius: 32px; max-width: 850px; padding: 3rem;">
           <button class="modal-close" onclick="window.app.closeEditPostModal()" style="top: 2rem; right: 2rem; font-size: 2rem;">&times;</button>
           <div style="margin-bottom: 2.5rem;">
              <h2 style="font-size: 2rem; font-weight: 800; color: #1E293B;">Edit Event Details</h2>
              <p style="color: #64748B; margin-top: 0.5rem;">Update the event information.</p>
           </div>
           <form onsubmit="window.app.handleEditPost(event)" style="display: grid; grid-template-columns: 1fr 1fr; gap: 2rem;">
              <input type="hidden" name="eventId" id="editEventId">
              <input type="hidden" name="image" id="editEventImage">
              
              <div class="form-group" style="grid-column: 1/-1;">
                 <label style="font-weight: 700; color: #334155; margin-bottom: 0.8rem;">Project Title</label>
                 <input type="text" name="title" id="editEventTitle" required style="border-radius: 12px; padding: 1rem; border: 1px solid #E2E8F0;">
              </div>
              <div class="form-group" style="grid-column: 1/-1;">
                 <label style="font-weight: 700; color: #334155; margin-bottom: 0.8rem;">Operational Briefing</label>
                 <textarea name="description" id="editEventDescription" required rows="4" style="border-radius: 12px; padding: 1rem; border: 1px solid #E2E8F0; resize: none;"></textarea>
              </div>
              <div class="form-group">
                  <label style="font-weight: 700; color: #334155;">Type</label>
                  <select name="type" id="editEventType" style="border-radius: 12px; padding: 1rem; border: 1px solid #E2E8F0;" onchange="this.nextElementSibling.style.display=this.value==='Other'?'block':'none'">
                      <option>Hackathon</option>
                      <option>Workshop</option>
                      <option>Session</option>
                      <option>Guest Lecture</option>
                      <option>Poster Presentation</option>
                      <option>Industry Visit</option>
                      <option>Other</option>
                  </select>
                  <input type="text" name="customType" id="editEventCustomType" placeholder="Enter custom event type" style="display:none; margin-top:0.5rem; width:100%; border-radius: 12px; padding: 1rem; border: 1px solid #E2E8F0;">
              </div>
              <div class="form-group"><label style="font-weight: 700; color: #334155;">Audience</label><select name="audience" id="editEventAudience" style="border-radius: 12px; padding: 1rem; border: 1px solid #E2E8F0;"><option>Student</option><option>Faculty</option><option>Both</option></select></div>
              <div class="form-group">
                  <label style="font-weight: 700; color: #334155;">Specialization</label>
                  <select name="department" id="editEventDepartment" style="border-radius: 12px; padding: 1rem; border: 1px solid #E2E8F0;">
                      <option>ALL</option>
                      <option>Computer</option>
                      <option>IT</option>
                      <option>ENTC</option>
                      <option>Electrical</option>
                      <option>Mechanical</option>
                      <option>AI & DS</option>
                      <option>FE</option>
                      <option>MCA</option>
                      <option>MBA</option>
                  </select>
              </div>
              <div class="form-group"><label style="font-weight: 700; color: #334155;">Release Deadline</label><input type="datetime-local" name="registrationDeadline" id="editEventDeadline" required style="border-radius: 12px; padding: 1rem; border: 1px solid #E2E8F0;"></div>
              <div class="form-group" style="grid-column: 1/-1;">
                 <label style="font-weight: 700; color: #334155;">Access Protocol</label>
                 <div style="display: flex; gap: 1rem; align-items: center; margin-top: 0.5rem;">
                    <select name="isPaid" id="editEventIsPaid" style="border-radius: 12px; padding: 1rem; border: 1px solid #E2E8F0; flex: 1;" onchange="this.nextElementSibling.style.display=this.value==='true'?'block':'none'"><option value="false">Open Access (Free)</option><option value="true">Premium Entry (Paid)</option></select>
                    <input type="number" name="price" id="editEventPrice" style="display:none; border-radius: 12px; padding: 1rem; border: 1px solid #E2E8F0; flex: 1;" value="0" placeholder="₹ Amount">
                 </div>
              </div>
              <div class="form-group" style="grid-column: 1/-1;">
                 <label style="font-weight: 700; color: #334155;">Visual Asset (Leave empty to keep current)</label>
                 <input type="file" name="imageFile" accept="image/*" style="border: 2px dashed #E2E8F0; padding: 2rem; border-radius: 20px; text-align: center; width: 100%; cursor: pointer;">
              </div>
              <button type="submit" class="btn btn-primary" style="grid-column: 1/-1; padding: 1.5rem; font-size: 1.2rem; border-radius: 18px; font-weight: 800; background: #2563EB;">Update Event Details</button>
           </form>
        </div>
      </div>
    </div>
  `;
};
