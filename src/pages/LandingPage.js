export const LandingPage = () => {
  return `
    <div class="landing-page" style="position: relative;">
      
      <!-- Zigzag Network Line Background Overlay -->
      <svg id="network-line-svg" viewBox="0 0 100 1000" preserveAspectRatio="none">
        <path class="network-path" d="M15,0 L15,100 L85,200 L15,350 L85,500 L25,650 L75,800 L50,1000" />
        <circle class="network-pulse-node" r="8" cx="15" cy="0" />
      </svg>

      <!-- Navbar -->
      <nav style="height: 90px; padding: 0 5%; display: flex; align-items: center; justify-content: space-between; position: fixed; width: 100%; top: 0; z-index: 1000; transition: all 0.4s ease;">
        <div class="logo" style="display: flex; align-items: center; gap: 0.8rem; text-decoration: none; cursor: pointer; padding-left: 10px;" onclick="window.scrollTo(0,0);">
          <img src="/logo.svg" alt="COGNI AI Logo" style="height: 65px; width: auto; filter: drop-shadow(0 4px 6px rgba(0,0,0,0.1));" onerror="this.src='/logo.svg'" />
          <span style="font-size: 1.6rem; color: var(--primary); font-weight: 800; font-family: 'Poppins', sans-serif;">COGNI AI</span>
        </div>
        <div class="nav-links" style="display: flex; gap: 2.5rem; align-items: center;">
          <a href="#about" style="text-decoration: none; color: var(--text-main); font-weight: 600; font-size: 0.95rem;">About</a>
          <a href="#objectives" style="text-decoration: none; color: var(--text-main); font-weight: 600; font-size: 0.95rem;">Objectives</a>
          <a href="#offerings" style="text-decoration: none; color: var(--text-main); font-weight: 600; font-size: 0.95rem;">Offerings</a>
          <button class="btn btn-outline" style="border-radius: 50px; font-size: 0.9rem;" onclick="window.app.navigate('login')">LogIn</button>
          <button class="btn btn-primary" style="border-radius: 50px; font-size: 0.9rem; padding: 0.75rem 1.8rem;" onclick="window.app.navigate('login')">Get Started</button>
        </div>
      </nav>

      <!-- 1. HERO SECTION -->
      <section class="hero" style="display: flex; align-items: center; background: white;">
        <!-- Animated Background Shapes -->
        <div class="bg-shape" style="width: 500px; height: 500px; background: rgba(37, 99, 235, 0.08); top: -10%; left: -10%;"></div>
        <div class="bg-shape" style="width: 400px; height: 400px; background: rgba(79, 70, 229, 0.08); bottom: -10%; right: -10%; animation-delay: -7s;"></div>

        <div class="container">
          <div class="hero-grid">
            <!-- Left Side: Content -->
            <div class="hero-content reveal stagger-1" style="z-index: 10;">
              <div class="section-tag" style="margin-bottom: 1.5rem;">Institutional Excellence 2026</div>
              <h1 class="hero-main-title">
                COGNI AI Forum –<br>
                <span style="background: var(--grad-primary); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">Together, Towards Excellence</span>
              </h1>
              <p style="font-size: 1.25rem; color: var(--accent); font-weight: 700; margin-bottom: 1rem; letter-spacing: -0.01em;">
                Empowering Ethical AI Learning, Innovation, and Industry Collaboration.
              </p>
              <p style="font-size: 1.1rem; color: var(--text-muted); line-height: 1.6; margin-bottom: 2rem; max-width: 550px;">
                COGNI AI Forum is a centralized academic platform designed to promote Artificial Intelligence awareness, interdisciplinary collaboration, research excellence, and real-world innovation.
              </p>
              <div style="display: flex; gap: 1rem; align-items: center; flex-wrap: wrap;">
                <button class="btn btn-primary" style="padding: 1rem 2.5rem; font-size: 1rem; border-radius: 50px; box-shadow: 0 10px 20px rgba(37, 99, 235, 0.2);">Explore Programs</button>
                <button class="btn btn-outline" style="padding: 1rem 2.5rem; font-size: 1rem; border-radius: 50px;" onclick="window.app.navigate('signup')">Join the Forum</button>
              </div>
            </div>

            <!-- Right Side: Professional Visual -->
            <div class="hero-visual-container reveal stagger-2">
              <div class="hero-glow-main"></div>
              
              <!-- Floating Glassmorphic Status Cards -->
              <div class="hero-status-card" style="top: 10%; right: 0;">
                <div style="width: 40px; height: 40px; background: var(--highlight); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1.2rem;">🚀</div>
                <div>
                  <div style="font-weight: 800; color: var(--text-main); font-size: 1.1rem;">Core Innovation</div>
                  <div style="font-size: 0.8rem; color: var(--text-muted);">2026 Research Drive</div>
                </div>
              </div>

              <div class="hero-status-card" style="bottom: 15%; left: -20px; animation-delay: -2s;">
                <div style="width: 40px; height: 40px; background: #ECFDF5; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1.2rem;">🛡️</div>
                <div>
                  <div style="font-weight: 800; color: var(--text-main); font-size: 1.1rem;">Ethical Framework</div>
                  <div style="font-size: 0.8rem; color: var(--text-muted);">NAAC Accredited</div>
                </div>
              </div>

              <!-- Main Visual Placeholder (Will be replaced by Generated Image) -->
              <div style="width: 100%; aspect-ratio: 1; min-width: 400px; background: var(--bg-card); border-radius: 60px; box-shadow: var(--shadow-soft); overflow: hidden; display: flex; align-items: center; justify-content: center; border: 1px solid var(--border); position: relative;">
                <img src="/images/hero-brain.png" alt="AI Neural Brain" style="width: 100%; height: 100%; object-fit: cover; opacity: 0.9;">
                <!-- Decorative Particles -->
                <div style="position: absolute; width: 10px; height: 10px; background: var(--primary); border-radius: 50%; top: 20%; left: 30%; filter: blur(2px);"></div>
                <div style="position: absolute; width: 15px; height: 15px; background: var(--accent); border-radius: 50%; bottom: 40%; right: 20%; filter: blur(3px);"></div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <!-- 2. ABOUT THE FORUM -->
      <section id="about" style="background: white; border-top: 1px solid var(--border);">
        <div class="container">
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 6rem; align-items: center;">
            <div class="reveal">
              <div class="section-tag">The Vision</div>
              <h2 style="font-size: 3.5rem; line-height: 1.1;">Building a Hybrid AI Learning Ecosystem</h2>
              <p style="font-size: 1.15rem; color: var(--text-muted); line-height: 2; margin-top: 2rem;">
                COGNI AI Forum is an institutional initiative aimed at transforming AI education through structured collaboration between students, faculty, and industry experts.
              </p>
              <p style="font-size: 1.15rem; color: var(--text-muted); line-height: 2; margin-top: 1.5rem;">
                The forum enables practical exposure, research-driven innovation, ethical AI awareness, and career-focused skill development through workshops, interdisciplinary projects, and expert mentorship.
              </p>
            </div>
            <div class="reveal stagger-1" style="position: relative; height: 500px;">
               <!-- AI Creative Slideshow -->
               <div class="creative-slideshow" id="about-slideshow">
                 <div class="slideshow-overlay"></div>
                 <img class="slide-img active" src="/images/hero-brain.png" alt="AI Neural Brain">
                  <img class="slide-img" src="/images/ai-lab.png" alt="Futuristic Academic Environment">
               </div>
               
               <div class="slideshow-content">
                 <div style="background: rgba(255, 255, 255, 0.9); padding: 2.5rem; border-radius: 24px; box-shadow: var(--shadow-soft); max-width: 400px; backdrop-filter: blur(10px);">
                    <div style="font-size: 3rem; margin-bottom: 1.5rem;" class="floating-icon">🌐</div>
                    <p style="font-weight: 700; font-size: 1.15rem; line-height: 1.6; color: var(--text-main);">It acts as a unified digital ecosystem for managing and monitoring all AI-related academic activities within the institution.</p>
                 </div>
               </div>
               
               <!-- Floating Detail -->
               <div style="position: absolute; top: -10px; right: -10px; padding: 1rem 2rem; background: var(--primary); color: white; border-radius: 50px; font-weight: 700; font-size: 0.9rem; box-shadow: var(--shadow-hover); z-index: 10;">Centralized Hub</div>
            </div>
          </div>
        </div>
      </section>
      <!-- 2.5 THE COGNI DNA ACRONYM -->
      <section id="dna" style="background: white; border-top: 1px solid var(--border); overflow: hidden; padding: 6rem 0;">
        <div class="container">
          <div class="section-title reveal" style="text-align: center; margin-bottom: 4rem;">
            <div class="section-tag" style="background: rgba(37,99,235,0.1); color: var(--primary);">Brand Identity</div>
            <h2 style="font-size: 3rem; margin-bottom: 1rem;">The COGNI AI DNA</h2>
            <p style="font-size: 1.15rem; color: var(--text-muted); max-width: 700px; margin: 0 auto;">The seven foundational pillars powering our intelligent academic ecosystem.</p>
          </div>
          
          <div class="dna-container reveal stagger-1">
            ${[
      { letter: 'C', word: 'Collaboration', icon: '🤝', desc: 'Fostering interdisciplinary teamwork and industry alliances.', bg: 'https://images.unsplash.com/photo-1522071820081-009f0129c71c?auto=format&fit=crop&q=80&w=600' },
      { letter: 'O', word: 'Opportunities', icon: '🚀', desc: 'Creating platforms for research, internships, and growth.', bg: 'https://images.unsplash.com/photo-1454165804606-c3d57bc86b40?auto=format&fit=crop&q=80&w=600' },
      { letter: 'G', word: 'Growth', icon: '📈', desc: 'Continuous advancement of skills and institutional capabilities.', bg: 'https://images.unsplash.com/photo-1460925895917-afdab827c52f?auto=format&fit=crop&q=80&w=600' },
      { letter: 'N', word: 'Networking', icon: '🌐', desc: 'Connecting students with expert mentors and visionaries.', bg: 'https://images.unsplash.com/photo-1451187580459-43490279c0fa?auto=format&fit=crop&q=80&w=600' },
      { letter: 'I', word: 'Innovation', icon: '💡', desc: 'Encouraging novel solutions to real-world challenges.', bg: 'https://images.unsplash.com/photo-1581091226825-a6a2a5aee158?auto=format&fit=crop&q=80&w=600' },
      { letter: 'A', word: 'Artificial Intelligence', icon: '🤖', desc: 'Mastering the core technologies shaping the future.', bg: 'https://images.unsplash.com/photo-1620712943543-bcc4688e7485?auto=format&fit=crop&q=80&w=600' },
      { letter: 'I', word: 'Intelligent Forum', icon: '🏛️', desc: 'A structured, smart ecosystem for academic excellence.', bg: 'https://images.unsplash.com/photo-1497366216548-37526070297c?auto=format&fit=crop&q=80&w=600' }
    ].map((item, index) => `
              <div class="dna-card" style="animation-delay: ${index * 0.1}s; background-image: url('${item.bg}');">
                <div class="dna-letter">${item.letter}</div>
                <div class="dna-content">
                  <div class="dna-icon">${item.icon}</div>
                  <h3 class="dna-word">${item.word}</h3>
                  <p class="dna-desc">${item.desc}</p>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      </section>

      <!-- 3. OUR CORE OBJECTIVES -->
      <section id="objectives" style="background: var(--lavender); border-radius: 80px;">
        <div class="container">
          <div class="section-title reveal" style="text-align: center; margin-bottom: 5rem;">
            <div class="section-tag">Mission Pulse</div>
            <h2>Our Core Objectives</h2>
          </div>
          <div class="grid grid-3">
            <div class="offering-card reveal stagger-1">
              <div class="offering-icon floating-icon">⚖️</div>
              <h3>Ethical Awareness</h3>
              <p style="color: var(--text-muted);">Develop ethical AI awareness and responsible technology practices across the academic spectrum.</p>
            </div>
            <div class="offering-card reveal stagger-2">
              <div class="offering-icon floating-icon" style="animation-delay: -1s;">🤝</div>
              <h3>Hybrid Collaboration</h3>
              <p style="color: var(--text-muted);">Create interdisciplinary AI collaboration across diverse departments and project groups.</p>
            </div>
            <div class="offering-card reveal stagger-3">
              <div class="offering-icon floating-icon" style="animation-delay: -2s;">⚡</div>
              <h3>Innovation Driven</h3>
              <p style="color: var(--text-muted);">Promote high-impact student projects and research through structured institutional support.</p>
            </div>
            <div class="offering-card reveal stagger-1" style="grid-column: span 1.5;">
              <div class="offering-icon floating-icon" style="animation-delay: -0.5s;">🏫</div>
              <h3>Industry Interaction</h3>
              <p style="color: var(--text-muted);">Enable direct industry-academia interaction to bridge the gap between classroom and career.</p>
            </div>
            <div class="offering-card reveal stagger-2" style="grid-column: span 1.5;">
              <div class="offering-icon floating-icon" style="animation-delay: -1.5s;">📊</div>
              <h3>Data Insights</h3>
              <p style="color: var(--text-muted);">Build data-driven academic performance insights to track and enhance institutional AI growth.</p>
            </div>
          </div>
        </div>
      </section>

      <!-- 4. WHAT WE OFFER -->
      <section id="offerings" style="background: white;">
        <div class="container">
          <div class="section-title reveal" style="text-align: center; margin-bottom: 6rem;">
            <div class="section-tag">Value Matrix</div>
            <h2>Dedicated Ecosystem Features</h2>
          </div>
          <div class="grid grid-3">
            <!-- For Students -->
            <div class="reveal stagger-1">
              <div class="offering-card" style="height: 100%;">
                 <div class="offering-icon">🎓</div>
                 <h3>For Students</h3>
                 <ul class="feature-list">
                   <li>Register for AI workshops & seminars</li>
                   <li>Apply for faculty-guided projects</li>
                   <li>Submit project milestones digitally</li>
                   <li>Access research materials & datasets</li>
                   <li>Track participation & skill growth</li>
                   <li>Download auto-generated certificates</li>
                   <li>View internship opportunities</li>
                 </ul>
              </div>
            </div>
            <!-- For Faculty -->
            <div class="reveal stagger-2">
              <div class="offering-card" style="height: 100%;">
                 <div class="offering-icon">👨‍🏫</div>
                 <h3>For Faculty</h3>
                 <ul class="feature-list">
                   <li>Post workshops & training programs</li>
                   <li>Create and mentor AI project groups</li>
                   <li>Evaluate student submissions</li>
                   <li>Upload research papers & materials</li>
                   <li>Monitor student participation</li>
                   <li>Generate performance reports</li>
                 </ul>
              </div>
            </div>
            <!-- For Admin -->
            <div class="reveal stagger-3">
              <div class="offering-card" style="height: 100%; border-color: var(--primary);">
                 <div class="offering-icon" style="background: var(--primary); color: white;">🛠️</div>
                 <h3>For Admin</h3>
                 <ul class="feature-list">
                   <li>Manage all users & authentication</li>
                   <li>Approve events and projects</li>
                   <li>Publish strategic announcements</li>
                   <li>Monitor forum activity analytics</li>
                   <li>Generate certificates automatically</li>
                   <li>Track institutional AI growth metrics</li>
                 </ul>
              </div>
            </div>
          </div>
        </div>
      </section>

      <!-- 5. LEADERSHIP & GOVERNANCE -->
      <section style="background: var(--bg-main);">
        <div class="container">
          <div class="section-title reveal" style="text-align: center; margin-bottom: 6rem;">
            <div class="section-tag">Governance</div>
            <h2>Forum Leadership & Committee</h2>
          </div>
          <div class="grid grid-3" style="gap: 3rem;">
            <div class="reveal stagger-1" style="text-align: center;">
               <div style="width: 180px; height: 180px; border-radius: 50%; overflow: hidden; margin: 0 auto 2rem; border: 4px solid white; box-shadow: var(--shadow-soft);">
                  <div style="width: 100%; height: 100%; background: var(--grad-primary); display: flex; align-items: center; justify-content: center; font-size: 5rem;">🏛️</div>
               </div>
               <h3 style="margin-bottom: 0.2rem;">Hon. Dr. T. J. Sawant</h3>
               <p style="color: var(--primary); font-weight: 700; font-size: 0.9rem;">Chief Patron</p>
            </div>
            <div class="reveal stagger-2" style="text-align: center;">
               <div style="width: 180px; height: 180px; border-radius: 50%; overflow: hidden; margin: 0 auto 2rem; border: 4px solid white; box-shadow: var(--shadow-soft);">
                  <div style="width: 100%; height: 100%; background: var(--grad-primary); display: flex; align-items: center; justify-content: center; font-size: 5rem;">🎓</div>
               </div>
               <h3 style="margin-bottom: 0.2rem;">Dr. P. A. Patil</h3>
               <p style="color: var(--primary); font-weight: 700; font-size: 0.9rem;">Chair Person (Principal JSCOE)</p>
            </div>
            <div class="reveal stagger-3" style="text-align: center;">
               <div style="width: 180px; height: 180px; border-radius: 50%; overflow: hidden; margin: 0 auto 2rem; border: 4px solid white; box-shadow: var(--shadow-soft);">
                  <div style="width: 100%; height: 100%; background: var(--grad-primary); display: flex; align-items: center; justify-content: center; font-size: 5rem;">🧬</div>
               </div>
               <h3 style="margin-bottom: 0.2rem;">Dr. M. K. Gawali</h3>
               <p style="color: var(--primary); font-weight: 700; font-size: 0.9rem;">Forum Coordinator</p>
            </div>
          </div>
          
          <div class="reveal stagger-1" style="margin-top: 5rem; padding: 4rem; background: white; border-radius: 40px; border: 1px solid var(--border); text-align: center;">
             <h4 style="font-size: 1.2rem; color: var(--text-main); margin-bottom: 2.5rem; letter-spacing: 0.1em; text-transform: uppercase;">Core Committee - Heads of Departments</h4>
             <div style="display: flex; flex-wrap: wrap; justify-content: center; gap: 1.5rem;">
                ${['ENTC', 'Computer', 'IT', 'Electrical', 'Mechanical', 'FE', 'MCA', 'MBA', 'AI & DS'].map(dept => `
                  <div style="padding: 1rem 2rem; background: var(--bg-main); border-radius: 50px; font-weight: 700; color: var(--text-muted); font-size: 0.9rem; border: 1px solid var(--border); transition: all 0.3s;" onmouseover="this.style.borderColor='var(--primary)'; this.style.color='var(--primary)'" onmouseout="this.style.borderColor='var(--border)'; this.style.color='var(--text-muted)'">${dept}</div>
                `).join('')}
             </div>
          </div>
        </div>
      </section>

      <!-- 6. IMPACT & GROWTH -->
      <section style="background: rgba(37, 99, 235, 0.03);">
        <div class="container">
          <div class="grid grid-5 reveal">
            <div style="text-align: center;">
              <span class="counter" style="color: var(--primary); font-size: 3.5rem; font-weight: 800;">500+</span>
              <p style="color: var(--text-muted); font-weight: 600; margin-top: 0.5rem; font-size: 0.9rem;">Students Engaged</p>
            </div>
            <div style="text-align: center;">
              <span class="counter" style="color: var(--primary); font-size: 3.5rem; font-weight: 800;">50+</span>
              <p style="color: var(--text-muted); font-weight: 600; margin-top: 0.5rem; font-size: 0.9rem;">AI Workshops</p>
            </div>
            <div style="text-align: center;">
              <span class="counter" style="color: var(--primary); font-size: 3.5rem; font-weight: 800;">25+</span>
              <p style="color: var(--text-muted); font-weight: 600; margin-top: 0.5rem; font-size: 0.9rem;">Faculty Mentors</p>
            </div>
            <div style="text-align: center;">
              <span class="counter" style="color: var(--primary); font-size: 3.5rem; font-weight: 800;">10+</span>
              <p style="color: var(--text-muted); font-weight: 600; margin-top: 0.5rem; font-size: 0.9rem;">Industry Experts</p>
            </div>
            <div style="text-align: center;">
              <span class="counter" style="color: var(--primary); font-size: 3.5rem; font-weight: 800;">100+</span>
              <p style="color: var(--text-muted); font-weight: 600; margin-top: 0.5rem; font-size: 0.9rem;">AI Projects</p>
            </div>
          </div>
        </div>
      </section>

      <!-- 7. WHY STANDS OUT -->
      <section style="background: white;">
        <div class="container">
           <div class="reveal" style="max-width: 900px; margin: 0 auto; text-align: center; background: var(--lavender); padding: 5rem; border-radius: 40px; border: 1px dashed var(--primary);">
              <h2 style="font-size: 2.2rem; line-height: 1.4; color: var(--text-main);">
                "COGNI AI Forum is not just an activity-based committee — it is a <span style="color: var(--primary);">structured, AI-powered digital ecosystem</span> that centralizes collaboration and enhances institutional performance."
              </h2>
           </div>
        </div>
      </section>

      <!-- 8. CALL TO ACTION -->
      <section style="padding: 0; margin-bottom: 5rem;">
        <div class="container">
          <div class="reveal" style="background: var(--grad-primary); border-radius: 50px; padding: 8rem 4rem; text-align: center; color: white; position: relative; overflow: hidden;">
            <div style="position: relative; z-index: 2;">
              <h2 style="color: white; font-size: 4rem; margin-bottom: 2rem;">Join the Future of Artificial Intelligence</h2>
              <div style="display: flex; gap: 1.5rem; justify-content: center; flex-wrap: wrap;">
                <button class="btn" style="background: white; color: var(--primary); padding: 1.2rem 3rem; border-radius: 50px; font-weight: 800;" onclick="window.app.navigate('signup')">Register as Student</button>
                <button class="btn btn-outline" style="border-color: white; color: white; padding: 1.2rem 3rem; border-radius: 50px; backdrop-filter: blur(10px);" onclick="window.app.navigate('login')">Faculty Login</button>
                <button class="btn btn-outline" style="border-color: white; color: white; padding: 1.2rem 3rem; border-radius: 50px; backdrop-filter: blur(10px);" onclick="window.app.navigate('login')">Admin Portal</button>
              </div>
            </div>
            <!-- Decorative Light Particles -->
            <div style="position: absolute; width: 100px; height: 100px; background: rgba(255,255,255,0.1); border-radius: 50%; top: 10%; left: 5%;"></div>
            <div style="position: absolute; width: 150px; height: 150px; background: rgba(255,255,255,0.1); border-radius: 50%; bottom: 10%; right: 5%;"></div>
          </div>
        </div>
      </section>

      <!-- 9. PROFESSIONAL FOOTER -->
      <footer>
        <div class="container">
          <div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 3rem; margin-bottom: 6rem;">
            <!-- Col 1 -->
            <div style="grid-column: span 1.5;">
              <h4 class="footer-nav-h">COGNI AI Forum</h4>
              <p style="line-height: 1.8; font-size: 0.95rem; margin-bottom: 2rem;">
                Dedicated to building ethical AI leaders through innovation, collaboration, and industry integration.
              </p>
              <div style="display: flex; flex-direction: column; gap: 0.8rem;">
                <div style="display: flex; align-items: center; gap: 0.8rem;">📧 <span>cogni.ai@college.edu</span></div>
                <div style="display: flex; align-items: center; gap: 0.8rem;">📍 <span>JSCOE Campus, Pune</span></div>
              </div>
            </div>
            <!-- Col 2 -->
            <div>
              <h4 class="footer-nav-h">Quick Links</h4>
              <a href="#" class="footer-link">Home</a>
              <a href="#about" class="footer-link">About</a>
              <a href="#" class="footer-link">Events</a>
              <a href="#" class="footer-link">Projects</a>
              <a href="#" class="footer-link">Research</a>
            </div>
            <!-- Col 3 -->
            <div>
              <h4 class="footer-nav-h">Programs</h4>
              <a href="#" class="footer-link">AI Workshops</a>
              <a href="#" class="footer-link">Research Initiatives</a>
              <a href="#" class="footer-link">Student Projects</a>
              <a href="#" class="footer-link">Industry Interaction</a>
              <a href="#" class="footer-link">Certifications</a>
            </div>
            <!-- Col 4 -->
            <div>
              <h4 class="footer-nav-h">Leadership</h4>
              <a href="#" class="footer-link">Chief Patron</a>
              <a href="#" class="footer-link">Chair Person</a>
              <a href="#" class="footer-link">Coordinator</a>
              <a href="#" class="footer-link">Core Committee</a>
            </div>
            <!-- Col 5 -->
            <div>
              <h4 class="footer-nav-h">Resources</h4>
              <a href="#" class="footer-link">AI Ethics Guidelines</a>
              <a href="#" class="footer-link">Forum Policies</a>
              <a href="#" class="footer-link">Privacy Policy</a>
              <a href="#" class="footer-link">Terms & Conditions</a>
            </div>
          </div>
          
          <div style="padding-top: 3rem; border-top: 1px solid rgba(255,255,255,0.05); display: flex; justify-content: space-between; align-items: center; font-size: 0.85rem;">
            <div>© 2026 COGNI AI Forum | All Rights Reserved</div>
            <div style="display: flex; gap: 1.5rem; align-items: center;">
              <span>Designed & Developed by COGNI AI Technical Team</span>
              <div style="display: flex; gap: 1rem;">
                <a href="#" style="color: white; text-decoration: none; opacity: 0.6;">LinkedIn</a>
                <a href="#" style="color: white; text-decoration: none; opacity: 0.6;">Email</a>
              </div>
            </div>
          </div>
        </div>
      </footer>
    </div>
  `;
};
