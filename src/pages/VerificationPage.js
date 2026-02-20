export const VerificationPage = (email) => {
  return `
    <div class="auth-page fade-in" style="background: radial-gradient(circle at top right, #F0F4FF, #F8FAFC);">
      <div class="auth-wrapper" style="max-width: 480px; width: 95%; margin: auto; grid-template-columns: 1fr; min-height: auto; box-shadow: 0 40px 100px -20px rgba(0,0,0,0.1); border-radius: 32px;">
        <div class="auth-content" style="width: 100%; padding: 4rem 3rem; align-items: center; justify-content: center;">
          <div class="auth-header" style="text-align: center; margin-bottom: 3rem;">
            <div style="width: 80px; height: 80px; background: #F0F4FF; border-radius: 24px; display: flex; align-items: center; justify-content: center; font-size: 2.5rem; margin: 0 auto 1.5rem; animation: floatingIcon 4s ease-in-out infinite;">📧</div>
            <h1 style="font-size: 2.5rem; font-weight: 800; color: #1E293B; margin-bottom: 0.8rem; letter-spacing: -0.02em;">Verify Account</h1>
            <p style="color: #64748B; font-size: 1rem; line-height: 1.6;">We've dispatched a secure code to<br><span style="color: #2563EB; font-weight: 700;">${email}</span></p>
          </div>

          <form onsubmit="window.app.handleVerification(event, '${email}')" style="width: 100%; display: grid; gap: 2rem;">
            <div class="form-group" style="text-align: center;">
              <label style="display: block; margin-bottom: 1.2rem; font-size: 0.85rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.1em; color: #94A3B8;">Identity Access Protocol</label>
              <div style="position: relative;">
                <input type="text" name="code" maxlength="6" placeholder="••••••" required 
                       style="width: 100%; text-align: center; font-family: 'Poppins', sans-serif; font-size: 2.5rem; font-weight: 800; letter-spacing: 0.4em; height: 85px; border-radius: 20px; border: 2px solid #E2E8F0; background: #F8FAFC; transition: all 0.3s ease; color: #1E293B; padding-left: 0.4em;"
                       onfocus="this.style.borderColor='#2563EB'; this.style.background='white'; this.style.boxShadow='0 0 0 4px rgba(37, 99, 235, 0.1)';"
                       onblur="this.style.borderColor='#E2E8F0'; this.style.background='#F8FAFC'; this.style.boxShadow='none';">
              </div>
            </div>
            
            <button type="submit" class="btn btn-primary auth-btn" style="padding: 1.4rem; font-size: 1.1rem; border-radius: 18px; font-weight: 800; background: #2563EB; box-shadow: 0 20px 25px -5px rgba(37, 99, 235, 0.4); letter-spacing: 0.05em;">Activate Profile</button>
            
            <div style="text-align: center; font-size: 0.95rem; color: #64748B; margin-top: 0.5rem;">
              Access issues? <a href="#" onclick="window.app.resendCode('${email}')" style="color: #2563EB; font-weight: 800; text-decoration: none; border-bottom: 2px solid #DBEAFE;">Reissue Code</a>
            </div>
          </form>
          
          <div class="auth-footer" style="margin-top: 3.5rem; text-align: center; border-top: 1px solid #F1F5F9; padding-top: 2rem;">
             <a href="#" onclick="window.app.navigate('signup')" style="color: #94A3B8; font-size: 0.9rem; font-weight: 600; text-decoration: none; display: flex; align-items: center; justify-content: center; gap: 0.5rem;">
                <span style="font-size: 1.2rem;">←</span> Return to Signup
             </a>
          </div>
        </div>
      </div>
    </div>
  `;
};
