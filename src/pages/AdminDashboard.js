export const AdminDashboard = (user, stats = {}) => {
   return `
    <div class="dashboard-container" style="background: #F8FAFC; min-height: 100vh; position: relative; overflow-x: hidden;">
      <div style="position: absolute; top: 0; left: 0; width: 100%; height: 400px; background: linear-gradient(135deg, #0F172A 0%, #1E293B 100%); z-index: 0; clip-path: polygon(0 0, 100% 0, 100% 85%, 0 100%);"></div>

      <nav style="position: relative; z-index: 10; padding: 1.5rem 5%; display: flex; justify-content: space-between; align-items: center; color: #1E293B;">
        <div class="logo" style="display: flex; align-items: center; gap: 0.8rem; text-decoration: none; cursor: pointer; color: #3B82F6;" onclick="window.scrollTo(0,0);">
          <div style="background: white; padding: 4px; border-radius: 8px; display: inline-flex; align-items: center; justify-content: center; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
            <img src="/src/assets/logo.svg" alt="COGNI AI Logo" style="height: 38px; width: auto;" onerror="this.src='/src/assets/logo.svg'" />
          </div>
          <span style="font-size: 1.5rem; font-weight: 800; font-family: 'Poppins', sans-serif;">COGNI AI <span style="font-weight: 500; opacity: 0.9; font-size: 1.1rem; color: #60A5FA;">ADMIN PANEL</span></span>
        </div>
        <div style="display: flex; gap: 1.5rem; align-items: center;">
          <span style="background: rgba(255,255,255,0.2); backdrop-filter: blur(5px); padding: 0.5rem 1rem; border-radius: 50px; font-size: 0.85rem; border: 1px solid rgba(255,255,255,0.3); color: white; font-weight: 600;">Verified Principal: ${user.name}</span>
          <button class="btn btn-primary" style="padding: 0.5rem 1.2rem; font-size: 0.8rem; border-radius: 50px; background: #EF4444; border: none; box-shadow: 0 4px 6px -1px rgba(239, 68, 68, 0.3);" onclick="window.app.logout()">Sign Out</button>
        </div>
      </nav>

      <div class="container" style="position: relative; z-index: 10; padding-bottom: 5rem;">
        <header style="margin-top: 3rem; margin-bottom: 4rem; display: flex; justify-content: space-between; align-items: center;">
          <div>
            <div style="background: #3B82F6; color: white; display: inline-block; padding: 0.4rem 1rem; border-radius: 6px; font-size: 0.75rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 1.2rem; box-shadow: 0 4px 6px -1px rgba(59, 130, 246, 0.3);">Administrative Control</div>
            <h1 style="font-size: 3.5rem; color: white; font-weight: 800; line-height: 1; letter-spacing: -0.02em;">Campus Activity <span style="color: #60A5FA;">Monitor</span></h1>
          </div>
          <div style="display: flex; gap: 1.2rem;">
             <button class="btn btn-primary" style="padding: 1rem 2rem; font-size: 1rem; border-radius: 16px; box-shadow: 0 20px 25px -5px rgba(37, 99, 235, 0.4);" onclick="window.app.showCreatePostModal()">+ Construct New Event</button>
          </div>
        </header>

        <div class="grid grid-3" style="gap: 2rem; margin-bottom: 0;">
          <div class="dashboard-card" style="border-radius: 24px; padding: 2.5rem; border: 1px solid rgba(255,255,255,0.1); background: rgba(255,255,255,0.9); backdrop-filter: blur(10px); box-shadow: 0 20px 25px -5px rgba(0,0,0,0.05);">
            <div style="font-size: 0.8rem; color: #64748B; font-weight: 800; text-transform: uppercase; margin-bottom: 1rem; letter-spacing: 0.05em;">Total Reach</div>
            <div style="font-size: 3.5rem; font-weight: 800; color: #1E293B;">${stats.totalUsers || 0}</div>
            <div style="font-size: 0.95rem; color: #64748B; margin-top: 0.5rem; font-weight: 500;">Registered Academic Profiles</div>
          </div>
          <div class="dashboard-card" style="border-radius: 24px; padding: 2.5rem; border: 1px solid rgba(255,255,255,0.1); background: rgba(255,255,255,0.9); backdrop-filter: blur(10px); box-shadow: 0 20px 25px -5px rgba(0,0,0,0.05);">
            <div style="font-size: 0.8rem; color: #64748B; font-weight: 800; text-transform: uppercase; margin-bottom: 1rem; letter-spacing: 0.05em;">Live Events</div>
            <div style="font-size: 3.5rem; font-weight: 800; color: #10B981;">${stats.totalEvents || 0}</div>
            <div style="font-size: 0.95rem; color: #64748B; margin-top: 0.5rem; font-weight: 500;">Active Campus Opportunities</div>
          </div>
          <div class="dashboard-card" style="border-radius: 24px; padding: 2.5rem; border: 1px solid rgba(255,255,255,0.1); background: rgba(255,255,255,0.9); backdrop-filter: blur(10px); box-shadow: 0 20px 25px -5px rgba(0,0,0,0.05);">
            <div style="font-size: 0.8rem; color: #64748B; font-weight: 800; text-transform: uppercase; margin-bottom: 1rem; letter-spacing: 0.05em;">Global Enrollments</div>
            <div style="font-size: 3.5rem; font-weight: 800; color: #F59E0B;">${stats.totalRegistrations || 0}</div>
            <div style="font-size: 0.95rem; color: #64748B; margin-top: 0.5rem; font-weight: 500;">Applications Processed</div>
          </div>
        </div>

        <!-- Monitoring Section: Expanded for "Big and Proper" look -->
        <section style="margin-top: 0;">
           <div style="background: white; border-radius: 32px; padding: 3rem; border: 1px solid var(--border); box-shadow: 0 10px 15px -3px rgba(0,0,0,0.04);">
              <div style="display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 4rem; padding-bottom: 2rem; border-bottom: 2px solid #F8FAFC;">
                 <div>
                    <h2 style="font-size: 2.2rem; font-weight: 800; color: #1E293B; letter-spacing: -0.02em;">Live Event Traction</h2>
                    <p style="color: #64748B; font-size: 1.1rem; margin-top: 0.5rem;">Real-time mobilization across all specialized campus streams.</p>
                 </div>
                 <div style="display: flex; gap: 1rem; align-items: center;">
                   <button class="btn btn-primary" style="padding: 1rem 2rem; font-size: 1rem; border-radius: 14px; background: #1E293B; border: none;" onclick="window.app.navigate('admin/analysis')">🔬 Open Analysis Center</button>
                   <span style="font-size: 0.85rem; background: #F0FDF4; color: #16A34A; padding: 0.6rem 1.2rem; border-radius: 50px; font-weight: 800; border: 1px solid #DCFCE7;">INTERNAL DATA SYNC ENABLED</span>
                 </div>
              </div>
              
              <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(450px, 1fr)); gap: 2.5rem;">
                 ${(stats.events || []).length > 0 ? (stats.events || []).map(event => `
                   <div style="padding: 2rem; border-radius: 24px; border: 1px solid #F1F5F9; background: #FFFFFF; display: flex; justify-content: space-between; align-items: center; transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1); cursor: pointer; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.02);" 
                        onmouseover="this.style.borderColor='var(--primary)'; this.style.transform='translateY(-8px)'; this.style.boxShadow='0 20px 25px -5px rgba(0,0,0,0.05)';" 
                        onmouseout="this.style.borderColor='#F1F5F9'; this.style.transform='none'; this.style.boxShadow='0 4px 6px -1px rgba(0,0,0,0.02)';">
                      <div style="display: flex; gap: 2rem; align-items: center;">
                         <div style="width: 100px; height: 100px; border-radius: 20px; overflow: hidden; background: white; border: 1px solid #E2E8F0; padding: 4px; background: #F8FAFC;">
                            <img src="${event.image || 'https://images.unsplash.com/photo-1591115765373-5207764f72e7?q=80&w=1000&auto=format&fit=crop'}" style="width: 100%; height: 100%; object-fit: cover; border-radius: 16px;">
                         </div>
                         <div>
                            <div style="display: inline-block; background: #EFF6FF; color: #2563EB; padding: 0.3rem 0.8rem; border-radius: 6px; font-size: 0.7rem; font-weight: 800; text-transform: uppercase; margin-bottom: 0.8rem;">${event.type}</div>
                            <h4 style="font-weight: 800; color: #1E293B; font-size: 1.4rem; line-height: 1.2;">${event.title}</h4>
                            <div style="display: flex; gap: 1rem; font-size: 0.9rem; color: #64748B; margin-top: 0.6rem;">
                               <span>📍 ${event.department === 'ALL' ? 'Open Access' : event.department}</span>
                            </div>
                         </div>
                      </div>
                      <div style="text-align: right; background: #F8FAFC; padding: 1.5rem; border-radius: 20px; border: 1px solid #F1F5F9; min-width: 140px;">
                         <div style="font-size: 2.2rem; font-weight: 800; color: var(--primary); line-height: 1;">${event.registrationCount || 0}</div>
                         <div style="font-size: 0.75rem; font-weight: 800; color: #94A3B8; text-transform: uppercase; margin-top: 0.4rem; letter-spacing: 0.05em;">Confirmed</div>
                      </div>
                   </div>
                 `).join('') : `
                   <div style="grid-column: 1/-1; padding: 10rem 0; text-align: center;">
                      <div style="font-size: 4rem; margin-bottom: 2rem;">📡</div>
                      <h3 style="font-size: 1.5rem; font-weight: 800; color: #1E293B;">No Active Traction Data</h3>
                      <p style="color: #64748B;">Please publish an event to begin receiving real-time enrollment analytics.</p>
                   </div>
                 `}
              </div>
           </div>
        </section>
      </div>

      <!-- Create Post Modal -->
      <div id="createPostModal" class="modal-overlay">
        <div class="modal-content" style="border-radius: 32px; max-width: 850px; padding: 3rem;">
           <button class="modal-close" onclick="window.app.closeCreatePostModal()" style="top: 2rem; right: 2rem; font-size: 2rem;">&times;</button>
           <div style="margin-bottom: 2.5rem;">
              <h2 style="font-size: 2rem; font-weight: 800; color: #1E293B;">Construct New Space</h2>
              <p style="color: #64748B; margin-top: 0.5rem;">Initiate a new collaborative platform for the campus community.</p>
           </div>
           <form onsubmit="window.app.handleCreatePost(event)" style="display: grid; grid-template-columns: 1fr 1fr; gap: 2rem;">
              <div class="form-group" style="grid-column: 1/-1;">
                 <label style="font-weight: 700; color: #334155; margin-bottom: 0.8rem;">Project Title</label>
                 <input type="text" name="title" required placeholder="e.g. InnovateX Hackathon" style="border-radius: 12px; padding: 1rem; border: 1px solid #E2E8F0;">
              </div>
              <div class="form-group" style="grid-column: 1/-1;">
                 <label style="font-weight: 700; color: #334155; margin-bottom: 0.8rem;">Operational Briefing</label>
                 <textarea name="description" required rows="4" placeholder="Detail the objectives and expectations..." style="border-radius: 12px; padding: 1rem; border: 1px solid #E2E8F0; resize: none;"></textarea>
              </div>
              <div class="form-group">
                  <label style="font-weight: 700; color: #334155;">Type</label>
                  <select name="type" style="border-radius: 12px; padding: 1rem; border: 1px solid #E2E8F0;" onchange="this.nextElementSibling.style.display=this.value==='Other'?'block':'none'">
                      <option>Hackathon</option>
                      <option>Workshop</option>
                      <option>Session</option>
                      <option>Guest Lecture</option>
                      <option>Poster Presentation</option>
                      <option>Industry Visit</option>
                      <option>Other</option>
                  </select>
                  <input type="text" name="customType" placeholder="Enter custom event type" style="display:none; margin-top:0.5rem; width:100%; border-radius: 12px; padding: 1rem; border: 1px solid #E2E8F0;">
              </div>
              <div class="form-group"><label style="font-weight: 700; color: #334155;">Audience</label><select name="audience" style="border-radius: 12px; padding: 1rem; border: 1px solid #E2E8F0;"><option>Student</option><option>Faculty</option><option>Both</option></select></div>
              <div class="form-group">
                  <label style="font-weight: 700; color: #334155;">Specialization</label>
                  <select name="department" style="border-radius: 12px; padding: 1rem; border: 1px solid #E2E8F0;">
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
              <div class="form-group"><label style="font-weight: 700; color: #334155;">Release Deadline</label><input type="datetime-local" name="registrationDeadline" required style="border-radius: 12px; padding: 1rem; border: 1px solid #E2E8F0;"></div>
              <div class="form-group" style="grid-column: 1/-1;">
                 <label style="font-weight: 700; color: #334155;">Access Protocol</label>
                 <div style="display: flex; gap: 1rem; align-items: center; margin-top: 0.5rem;">
                    <select name="isPaid" style="border-radius: 12px; padding: 1rem; border: 1px solid #E2E8F0; flex: 1;" onchange="this.nextElementSibling.style.display=this.value==='true'?'block':'none'"><option value="false">Open Access (Free)</option><option value="true">Premium Entry (Paid)</option></select>
                    <input type="number" name="price" style="display:none; border-radius: 12px; padding: 1rem; border: 1px solid #E2E8F0; flex: 1;" value="0" placeholder="₹ Amount">
                 </div>
              </div>
              <div class="form-group" style="grid-column: 1/-1;">
                 <label style="font-weight: 700; color: #334155;">Visual Asset</label>
                 <input type="file" name="imageFile" accept="image/*" style="border: 2px dashed #E2E8F0; padding: 2rem; border-radius: 20px; text-align: center; width: 100%; cursor: pointer;">
              </div>
              <button type="submit" class="btn btn-primary" style="grid-column: 1/-1; padding: 1.5rem; font-size: 1.2rem; border-radius: 18px; font-weight: 800; background: #2563EB; box-shadow: 0 10px 15px -3px rgba(37, 99, 235, 0.4);">Authorize & Publish Globally</button>
           </form>
        </div>
      </div>
    </div>
  `;
};
