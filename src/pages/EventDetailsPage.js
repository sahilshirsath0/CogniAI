export const EventDetailsPage = (event, user, invitation = null) => {
   if (!event) return '<div class="container" style="padding: 4rem; text-align: center;">Loading event details...</div>';

   const isClosed = new Date() > new Date(event.registrationDeadline);
   const formattedDate = new Date(event.registrationDeadline).toLocaleString('en-US', {
      weekday: 'long', year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit'
   });

   const isJoiningTeam = invitation !== null;

   return `
    <div class="student-dashboard" style="background: #F8FAFC; min-height: 100vh;">
      <nav class="student-nav" style="background: white; border-bottom: 1px solid var(--border); padding: 1rem 5%; display: flex; justify-content: space-between; align-items: center;">
        <div class="logo" style="cursor: pointer; color: var(--primary); font-weight: 800; font-size: 1.2rem;" onclick="window.app.navigate(window.app.user.role === 'student' ? 'student-dashboard' : 'dashboard')">← BACK TO FEED</div>
        <div class="nav-links">
          <button class="logout-btn-minimal" style="color: var(--text-muted);" onclick="window.app.logout()">Sign Out</button>
        </div>
      </nav>

      <div class="container" style="padding: 2rem 5%; display: flex; gap: 3rem; align-items: flex-start;">
        <!-- Left Side: Event Details -->
        <div style="flex: 1.2; position: sticky; top: 2rem;">
           <div class="dashboard-card" style="padding: 0; overflow: hidden; border-radius: 24px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.05);">
              <img src="${event.image || 'https://images.unsplash.com/photo-1620712943543-bcc4688e7485?q=80&w=1000&auto=format&fit=crop'}" style="width: 100%; height: 400px; object-fit: cover;">
              <div style="padding: 2.5rem;">
                 <div style="display: flex; gap: 0.8rem; margin-bottom: 1.5rem;">
                    <span style="background: var(--highlight); color: var(--primary); padding: 0.5rem 1.2rem; border-radius: 50px; font-size: 0.8rem; font-weight: 800; text-transform: uppercase;">${event.type}</span>
                    <span style="background: #F0FDF4; color: #16A34A; padding: 0.5rem 1.2rem; border-radius: 50px; font-size: 0.8rem; font-weight: 800; text-transform: uppercase;">${event.isPaid ? `Paid Event (₹${event.price})` : 'Free Entry'}</span>
                 </div>
                 <h1 style="font-size: 2.8rem; line-height: 1.1; margin-bottom: 1.5rem; font-weight: 800; color: #1E293B;">${event.title}</h1>
                 ${invitation ? `<div style="background: #E0F2FE; color: #0369A1; padding: 1rem; border-radius: 12px; margin-bottom: 1.5rem; border: 1px solid #BAE6FD; font-weight: 700;">🤝 Joining team: ${invitation.teamName}</div>` : ''}
                 <p style="font-size: 1.1rem; color: #64748B; line-height: 1.8; margin-bottom: 2rem; white-space: pre-line;">${event.description}</p>
                 
                 <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 2rem; padding: 2rem; background: #F8FAFC; border-radius: 20px; border: 1px solid var(--border);">
                    <div>
                        <div style="font-size: 0.75rem; color: var(--text-muted); font-weight: 800; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem;">Deadline</div>
                        <div style="font-weight: 700; color: #1E293B;">${formattedDate}</div>
                    </div>
                    <div>
                        <div style="font-size: 0.75rem; color: var(--text-muted); font-weight: 800; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem;">Audience</div>
                        <div style="font-weight: 700; color: #1E293B;">${event.audience}</div>
                    </div>
                 </div>
              </div>
           </div>
        </div>

        <!-- Right Side: Registration Form -->
        <div style="flex: 0.8; background: white; border-radius: 24px; padding: 2.5rem; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); border: 1px solid var(--border);">
           <h2 style="font-size: 1.5rem; font-weight: 800; margin-bottom: 0.5rem; color: #1E293B;">${isJoiningTeam ? 'Complete Team Enrollment' : 'Secure Your Spot'}</h2>
           <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 2rem;">Help your team succeed by providing your details for ${event.title}</p>
           
           <form onsubmit="window.app.handleComprehensiveRegistration(event, '${event._id}')" id="comprehensiveRegistrationForm">
              <input type="hidden" name="invitationId" value="${invitation?._id || ''}">
              
              <div class="form-group" style="margin-bottom: 1.5rem;">
                 <label>Full Name</label>
                 <input type="text" value="${user.name}" disabled style="background: #f1f5f9; cursor: not-allowed; border-radius: 12px; padding: 0.8rem;">
              </div>
              
              <div class="grid grid-2" style="gap: 1rem; margin-bottom: 1.5rem;">
                 ${user.role === 'faculty' ? `
                    <div class="form-group" style="grid-column: 1 / -1;">
                        <label>Department</label>
                        <select name="dept" required style="border-radius: 12px; padding: 0.8rem;">
                           <option value="${user.dept}" selected>${user.dept}</option>
                           <option value="Computer">Computer</option>
                           <option value="IT">IT</option>
                           <option value="ENTC">ENTC</option>
                           <option value="Mechanical">Mechanical</option>
                           <option value="Electrical">Electrical</option>
                           <option value="AI & DS">AI & DS</option>
                        </select>
                    </div>
                 ` : `
                    <div class="form-group">
                        <label>Roll Number</label>
                        <input type="text" name="rollno" value="${user.rollno || ''}" required placeholder="e.g. 21CO042" style="border-radius: 12px; padding: 0.8rem;">
                    </div>
                    <div class="form-group">
                        <label>Academic Class</label>
                        <select name="classYear" required style="border-radius: 12px; padding: 0.8rem;">
                           <option value="SE" ${user.year === 'SE' ? 'selected' : ''}>SE (Second Year)</option>
                           <option value="TE" ${user.year === 'TE' ? 'selected' : ''}>TE (Third Year)</option>
                           <option value="BE" ${user.year === 'BE' ? 'selected' : ''}>BE (Fourth Year)</option>
                        </select>
                    </div>
                 `}
              </div>

              ${user.role !== 'faculty' ? `
              <div class="form-group" style="margin-bottom: 1.5rem; ${isJoiningTeam ? 'display: none;' : ''}">
                 <label style="margin-bottom: 0.5rem;">Participation Type</label>
                 <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                    <label class="radio-card" style="display: flex; align-items: center; justify-content: center; gap: 0.8rem; cursor: pointer; background: #F8FAFC; padding: 1rem; border-radius: 12px; border: 1px solid var(--border); transition: all 0.2s;">
                       <input type="radio" name="registrationType" value="Individual" ${!isJoiningTeam ? 'checked' : ''} onchange="document.getElementById('teamFields').style.display='none'" style="width: auto; margin: 0;"> 
                       <span style="font-weight: 600;">Individual</span>
                    </label>
                    <label class="radio-card" style="display: flex; align-items: center; justify-content: center; gap: 0.8rem; cursor: pointer; background: #F8FAFC; padding: 1rem; border-radius: 12px; border: 1px solid var(--border); transition: all 0.2s;">
                       <input type="radio" name="registrationType" value="Team" ${isJoiningTeam ? 'checked' : ''} onchange="document.getElementById('teamFields').style.display='block'" style="width: auto; margin: 0;"> 
                       <span style="font-weight: 600;">Team / Group</span>
                    </label>
                 </div>
              </div>

              ${isJoiningTeam ? `<input type="hidden" name="registrationType" value="Team">` : ''}

              <div id="teamFields" style="display: ${isJoiningTeam ? 'block' : 'none'}; background: #EFF6FF; padding: 1.5rem; border-radius: 12px; border: 1px solid #BFDBFE; margin-bottom: 1.5rem;">
                 <div class="form-group" style="margin-bottom: 1rem;">
                    <label style="color: #1E40AF;">Team Name</label>
                    <input type="text" name="teamName" value="${invitation?.teamName || ''}" ${isJoiningTeam ? 'readonly' : ''} placeholder="e.g. Cyber Ninjas" style="border-radius: 12px; padding: 0.8rem; border-color: #93C5FD; ${isJoiningTeam ? 'background: #DBEAFE; cursor: not-allowed;' : ''}">
                 </div>
                 
                 <div class="form-group" style="${isJoiningTeam ? 'display: none;' : ''}">
                    <label style="color: #1E40AF;">Add Members (by College Email)</label>
                    <div style="display: flex; gap: 0.5rem;">
                       <input type="email" id="memberEmailInput" placeholder="teammate@college.edu" style="flex: 1; border-radius: 12px; padding: 0.8rem; border-color: #93C5FD;">
                       <button type="button" class="btn btn-primary" onclick="window.app.addTeamMemberInvitation('${event._id}')" style="padding: 0.8rem 1.2rem;">Add</button>
                    </div>
                    <div id="tempMemberList" style="margin-top: 1rem; display: flex; flex-wrap: wrap; gap: 0.5rem;"></div>
                    <input type="hidden" name="teamMembers" id="teamMembersData" value="[]">
                 </div>
                 ${isJoiningTeam ? '<p style="font-size: 0.8rem; color: #1E40AF; font-weight: 600;">✓ You are joining an existing squad</p>' : ''}
              </div>
              ` : `<input type="hidden" name="registrationType" value="Individual">`}

              <div style="margin-bottom: 1.5rem;">
                 <label style="display: flex; align-items: center; gap: 0.5rem; cursor: pointer; font-size: 0.85rem; color: var(--text-muted);">
                    <input type="checkbox" required checked>
                    I accept the privacy policy and event terms.
                 </label>
              </div>

              <button type="submit" class="btn btn-primary" style="width: 100%; padding: 1rem; font-size: 1.1rem; justify-content: center; border-radius: 16px; box-shadow: 0 10px 15px -3px rgba(37, 99, 235, 0.3);" ${isClosed ? 'disabled' : ''}>
                 ${isJoiningTeam ? 'Accept Invite & Join Team' : (isClosed ? 'Registration Closed' : 'Confirm & Register')}
              </button>
           </form>
        </div>
      </div>
    </div>
  `;
};
