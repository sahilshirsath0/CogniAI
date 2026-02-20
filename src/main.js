import "./style.css";
import { LandingPage } from "./pages/LandingPage";
import { LoginPage } from "./pages/LoginPage";
import { AdminDashboard } from "./pages/AdminDashboard";
import { FacultyDashboard } from "./pages/FacultyDashboard";
import { StudentDashboard } from "./pages/StudentDashboard";
import { SignupPage } from "./pages/SignupPage";
import { EventDetailsPage } from "./pages/EventDetailsPage";
import { AdminAnalysisPage } from "./pages/AdminAnalysisPage";
import { VerificationPage } from "./pages/VerificationPage";

class App {
  constructor() {
    this.appElement = document.querySelector("#app");
    this.user = JSON.parse(localStorage.getItem("cogni_user")) || null;
    this.filters = { isPaid: null, department: null, type: null };
    this.selectedEventStats = null;
    this.pendingVerificationEmail = null;
    window.addEventListener("scroll", () => this.handleScroll());
    window.addEventListener("popstate", () => this.render());
    this.init();
  }

  init() {
    window.app = this;
    this.render();
  }

  navigate(page) {
    window.history.pushState({}, "", `/${page}`);
    this.render();
  }

  async handleLogin(event) {
    event.preventDefault();
    const formData = new FormData(event.target);
    const data = Object.fromEntries(formData.entries());

    try {
      const response = await fetch("http://localhost:5000/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });

      const result = await response.json();

      if (response.ok) {
        localStorage.setItem("cogni_user", JSON.stringify(result.user));
        localStorage.setItem("cogni_token", result.token);
        this.user = result.user;
        const targetPage =
          result.user.role === "student" ? "student-dashboard" : "dashboard";
        window.history.pushState({}, "", `/${targetPage}`);
        this.render();
      } else {
        if (result.needsVerification) {
          this.pendingVerificationEmail = result.email;
          this.render();
          return;
        }
        alert(result.message || "Login failed");
      }
    } catch (error) {
      alert("Login failed");
    }
  }

  async handleSignup(event, role) {
    event.preventDefault();
    const formData = new FormData(event.target);
    const data = Object.fromEntries(formData.entries());
    data.role = role;

    if (data.password !== data.retype && role === "student") {
      alert("Passwords do not match!");
      return;
    }

    try {
      const response = await fetch("http://localhost:5000/api/auth/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });

      const result = await response.json();

      if (response.ok) {
        this.pendingVerificationEmail = data.email;
        this.render();
      } else {
        alert(result.message || "Signup failed");
      }
    } catch (error) {
      alert("Signup failed");
    }
  }

  async handleVerification(event, email) {
    event.preventDefault();
    const code = event.target.code.value;

    try {
      const response = await fetch("http://localhost:5000/api/auth/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, code }),
      });

      const result = await response.json();

      if (response.ok) {
        alert(result.message);
        this.pendingVerificationEmail = null;
        this.navigate("login");
      } else {
        alert(result.message || "Verification failed");
      }
    } catch (error) {
      alert("Verification failed");
    }
  }

  async resendCode(email) {
    // Implement resend logic on backend if needed
    alert("Resending code to " + email);
  }

  switchSignupRole(role) {
    // Update tabs
    document.querySelectorAll(".role-tab").forEach((tab) => {
      tab.classList.remove("active");
      if (tab.innerText.toLowerCase() === role) {
        tab.classList.add("active");
      }
    });

    // Update forms
    document.querySelectorAll(".signup-form").forEach((form) => {
      form.style.display = "none";
    });
    document.getElementById(`${role}SignupForm`).style.display = "block";
  }

  logout() {
    localStorage.removeItem("cogni_user");
    this.user = null;
    window.history.pushState({}, "", "/");
    this.render();
  }

  openModal(type) {
    alert(`This would open the ${type} creation modal in the full version!`);
  }

  showCreatePostModal() {
    const modal = document.getElementById("createPostModal");
    modal.style.display = "flex";
    // Small timeout to allow display change to render before adding active class for transition
    setTimeout(() => modal.classList.add("active"), 10);
  }

  closeCreatePostModal() {
    const modal = document.getElementById("createPostModal");
    modal.classList.remove("active");
    // Wait for transition to finish before hiding
    setTimeout(() => (modal.style.display = "none"), 300);
  }

  showEditProfileModal() {
    const modal = document.getElementById("editProfileModal");
    modal.style.display = "flex";
    setTimeout(() => modal.classList.add("active"), 10);
  }

  closeEditProfileModal() {
    const modal = document.getElementById("editProfileModal");
    modal.classList.remove("active");
    setTimeout(() => (modal.style.display = "none"), 300);
  }

  async handleEditProfile(event) {
    event.preventDefault();
    const formData = new FormData(event.target);
    const data = Object.fromEntries(formData.entries());

    // Add user ID to request
    data.userId = this.user.id; // Or _id depending on what's stored

    try {
      const response = await fetch("http://localhost:5000/api/users/profile", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });

      const result = await response.json();

      if (response.ok) {
        alert("Profile updated successfully!");
        // Update local storage and current user
        this.user = { ...this.user, ...result.user }; // Update only changed fields
        localStorage.setItem("cogni_user", JSON.stringify(this.user));

        this.closeEditProfileModal();
        this.render(); // Refresh dashboards
      } else {
        alert(result.message || "Update failed");
      }
    } catch (error) {
      console.error("Update Profile Error:", error);
      alert("Could not connect to server");
    }
  }

  async addTeamMemberInvitation(eventId) {
    const emailInput = document.getElementById("memberEmailInput");
    const email = emailInput.value.trim();
    if (!email) return;

    try {
      const response = await fetch(
        `http://localhost:5000/api/users/search?email=${email}`,
      );
      const user = await response.json();

      if (response.ok) {
        const list = document.getElementById("tempMemberList");
        const dataInput = document.getElementById("teamMembersData");
        const currentMembers = JSON.parse(dataInput.value);

        if (currentMembers.includes(email)) {
          alert("Member already added");
          return;
        }

        currentMembers.push(email);
        dataInput.value = JSON.stringify(currentMembers);

        const pill = document.createElement("div");
        pill.className = "filter-chip active";
        pill.style.display = "flex";
        pill.style.alignItems = "center";
        pill.style.gap = "0.5rem";
        pill.innerHTML = `<span>${user.name}</span> <span style="cursor:pointer" onclick="this.parentElement.remove()">×</span>`;
        list.appendChild(pill);
        emailInput.value = "";
      } else {
        alert(user.message || "User not found");
      }
    } catch (error) {
      alert("Search failed");
    }
  }

  async handleComprehensiveRegistration(event, eventId) {
    event.preventDefault();
    const formData = new FormData(event.target);
    const data = Object.fromEntries(formData.entries());

    // Add additional payload
    const payload = {
      userId: this.user.id,
      eventId,
      registrationType: data.registrationType,
      teamName: data.teamName,
      classYear: data.classYear,
      rollno: data.rollno,
      invitationId: data.invitationId,
      teamMembersEmails: JSON.parse(data.teamMembers || "[]"),
    };

    try {
      const response = await fetch("http://localhost:5000/api/registrations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const result = await response.json();

      if (response.ok) {
        // If team, send invitations
        if (payload.registrationType === "Team") {
          const membersStr = document.getElementById("teamMembersData").value;
          const members = JSON.parse(membersStr || "[]");
          for (const email of members) {
            await fetch("http://localhost:5000/api/teams/invite", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                fromUserId: this.user.id,
                toEmail: email,
                eventId,
                teamName: payload.teamName,
              }),
            });
          }
        }

        alert("Registration Successful!");
        window.history.pushState({}, "", "/student-dashboard");
        this.render();
      } else {
        alert(result.message || "Registration failed");
      }
    } catch (error) {
      alert("Network error");
    }
  }

  async handleCreatePost(event) {
    event.preventDefault();
    const formData = new FormData(event.target);

    // Handle "Other" type
    if (formData.get("type") === "Other") {
      const customType = formData.get("customType");
      if (customType) {
        formData.set("type", customType);
      }
    }

    try {
      const response = await fetch("http://localhost:5000/api/events", {
        method: "POST",
        body: formData,
      });
      if (response.ok) {
        alert("Event created successfully!");
        this.closeCreatePostModal();
        this.render();
      } else {
        const error = await response.json();
        alert(`Failed: ${error.message}`);
      }
    } catch (error) {
      alert("Error connecting to server");
    }
  }

  async deleteEvent(eventId) {
    if (!confirm("Are you sure?")) return;
    try {
      const response = await fetch(
        `http://localhost:5000/api/events/${eventId}`,
        {
          method: "DELETE",
        },
      );
      if (response.ok) {
        alert("Event deleted");
        this.render();
      }
    } catch (error) {
      alert("Error");
    }
  }

  async openEditPostModal(eventId) {
    try {
      const response = await fetch(
        `http://localhost:5000/api/events/${eventId}`,
      );
      const event = await response.json();
      document.getElementById("editEventId").value = event._id;
      document.getElementById("editEventTitle").value = event.title;
      document.getElementById("editEventDescription").value = event.description;

      // Handle Type selection
      const typeSelect = document.getElementById("editEventType");
      const customTypeInput = document.getElementById("editEventCustomType");
      const standardTypes = [
        "Hackathon",
        "Workshop",
        "Session",
        "Guest Lecture",
        "Poster Presentation",
        "Industry Visit",
      ];

      if (standardTypes.includes(event.type)) {
        typeSelect.value = event.type;
        customTypeInput.style.display = "none";
        customTypeInput.value = "";
      } else {
        typeSelect.value = "Other";
        customTypeInput.style.display = "block";
        customTypeInput.value = event.type;
      }

      document.getElementById("editEventAudience").value = event.audience;
      document.getElementById("editEventDepartment").value = event.department;
      document.getElementById("editEventDeadline").value = new Date(
        event.registrationDeadline,
      )
        .toISOString()
        .slice(0, 16);
      document.getElementById("editEventImage").value = event.image;
      document.getElementById("editEventIsPaid").value =
        event.isPaid.toString();
      const priceInput = document.getElementById("editEventPrice");
      priceInput.value = event.price || 0;
      priceInput.style.display = event.isPaid ? "block" : "none";
      const modal = document.getElementById("editPostModal");
      modal.style.display = "flex";
      setTimeout(() => modal.classList.add("active"), 10);
    } catch (error) {
      alert("Failed to load event");
    }
  }

  closeEditPostModal() {
    const modal = document.getElementById("editPostModal");
    modal.classList.remove("active");
    setTimeout(() => (modal.style.display = "none"), 300);
  }

  async handleEditPost(event) {
    event.preventDefault();
    const formData = new FormData(event.target);
    const data = Object.fromEntries(formData.entries());

    // Handle "Other" type
    if (data.type === "Other" && data.customType) {
      data.type = data.customType;
    }

    try {
      const response = await fetch(
        `http://localhost:5000/api/events/${data.eventId}`,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(data),
        },
      );
      if (response.ok) {
        alert("Updated!");
        this.closeEditPostModal();
        this.render();
      }
    } catch (error) {
      alert("Error");
    }
  }

  startAboutSlideshow() {
    const slideshow = document.getElementById("about-slideshow");
    if (!slideshow) return;
    const images = slideshow.querySelectorAll(".slide-img");
    let currentIndex = 0;
    if (this.aboutInterval) clearInterval(this.aboutInterval);
    this.aboutInterval = setInterval(() => {
      images[currentIndex].classList.remove("active");
      currentIndex = (currentIndex + 1) % images.length;
      images[currentIndex].classList.add("active");
    }, 5000);
  }

  handleUnifiedFilter(value) {
    this.filters = { isPaid: null, department: null, type: null };
    if (value === "all") {
    } else if (value === "free") this.filters.isPaid = false;
    else if (value === "paid") this.filters.isPaid = true;
    else if (value.startsWith("dept:"))
      this.filters.department = value.split(":")[1];
    else if (value.startsWith("type:")) this.filters.type = value.split(":")[1];
    this.render();
  }

  async fetchEventAnalysis(eventId) {
    try {
      const eventRes = await fetch(
        `http://localhost:5000/api/events/${eventId}`,
      );
      const event = await eventRes.json();

      const analRes = await fetch(
        `http://localhost:5000/api/admin/analytics?eventId=${eventId}`,
      );
      const analytics = await analRes.json();

      this.selectedEventStats = {
        ...analytics,
        eventId,
        title: event.title,
      };
      this.render();
    } catch (error) {
      alert("Analysis failed");
    }
  }

  async respondToInvitation(invId, status) {
    try {
      const response = await fetch(
        `http://localhost:5000/api/teams/invitations/${invId}/respond`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ status, userId: this.user.id }),
        },
      );
      if (response.ok) {
        alert(`Invitation ${status}!`);
        this.render();
      }
    } catch (error) {
      alert("Action failed");
    }
  }

  async confirmTeam(regId) {
    try {
      const response = await fetch(
        `http://localhost:5000/api/teams/confirm/${regId}`,
        {
          method: "POST",
        },
      );
      if (response.ok) {
        alert("Team confirmed!");
        this.render();
      }
    } catch (error) {
      alert("Confirmation failed");
    }
  }

  renderAnalysisScreen() {
    this.selectedEventStats = null;
    this.render();
  }

  async render() {
    const path = window.location.pathname;

    if (this.pendingVerificationEmail) {
      this.appElement.innerHTML = VerificationPage(
        this.pendingVerificationEmail,
      );
      return;
    }

    if (!this.user) {
      if (path === "/login") {
        this.appElement.innerHTML = LoginPage();
      } else if (path === "/signup") {
        this.appElement.innerHTML = SignupPage();
      } else {
        this.appElement.innerHTML = LandingPage();
        this.animateCounters();
        this.startCarousel();
        this.initScrollAnimations();
        this.startAboutSlideshow();
      }
      this.handleScroll();
      return;
    }

    // Handle Admin Analysis Route
    if (path === "/admin/analysis" || path === "admin/analysis") {
      const allEvents = await this.fetchEvents(); // Get ALL events
      this.appElement.innerHTML = AdminAnalysisPage(
        this.user,
        allEvents,
        this.selectedEventStats,
      );
      return;
    }

    // Handle Event Details Route
    if (path.startsWith("/event/")) {
      const eventId = path.split("/")[2];
      const urlParams = new URLSearchParams(window.location.search);
      const invId = urlParams.get("invId");

      try {
        const response = await fetch(
          `http://localhost:5000/api/events/${eventId}`,
        );
        const event = await response.json();

        let invitation = null;
        if (invId) {
          // Fetch invitation details if needed, or we can just pass the ID and dummy data
          // For simplicity, let's fetch my invitations and find this one
          const invs = await this.fetchTeamInvitations(this.user.id);
          invitation = invs.find((i) => i._id === invId);
        }

        this.appElement.innerHTML = EventDetailsPage(
          event,
          this.user,
          invitation,
        );
      } catch (error) {
        console.error("Error fetching event details:", error);
        this.appElement.innerHTML =
          '<div class="container" style="padding: 4rem;"><h3>Event not found</h3></div>';
      }
      return;
    }

    // Role-based routing with data fetching
    switch (this.user.role) {
      case "admin":
        const stats = await this.fetchStats();
        this.appElement.innerHTML = AdminDashboard(this.user, stats);
        break;
      case "faculty":
        const facultyEvents = await this.fetchEvents("Faculty");
        const facultyRegistrations = await this.fetchRegistrations(
          this.user.id,
        );
        this.appElement.innerHTML = FacultyDashboard(
          this.user,
          facultyEvents,
          facultyRegistrations,
        );
        break;
      case "student":
        const studentEvents = await this.fetchEvents("Student");
        const studentRegistrations = await this.fetchRegistrations(
          this.user.id,
        );
        const invitations = await this.fetchTeamInvitations(this.user.id);
        this.appElement.innerHTML = StudentDashboard(
          this.user,
          studentEvents,
          studentRegistrations,
          this.filters,
          invitations,
        );
        break;
      default:
        this.appElement.innerHTML = LandingPage();
    }

    this.handleScroll();
  }

  async fetchTeamInvitations(userId) {
    try {
      const response = await fetch(
        `http://localhost:5000/api/teams/invitations/${userId}`,
      );
      return await response.json();
    } catch (error) {
      return [];
    }
  }

  async fetchEvents(audience = null) {
    try {
      let url = "http://localhost:5000/api/events";
      const params = new URLSearchParams();
      if (audience) params.append("audience", audience);
      if (this.filters.isPaid !== null)
        params.append("isPaid", this.filters.isPaid);
      if (this.filters.department)
        params.append("department", this.filters.department);
      if (this.filters.type) params.append("type", this.filters.type);

      const queryString = params.toString();
      if (queryString) url += "?" + queryString;

      const response = await fetch(url);
      return await response.json();
    } catch (error) {
      console.error("Error fetching events:", error);
      return [];
    }
  }

  async fetchRegistrations(userId) {
    try {
      const response = await fetch(
        `http://localhost:5000/api/registrations/user/${userId}`,
      );
      return await response.json();
    } catch (error) {
      console.error("Error fetching registrations:", error);
      return [];
    }
  }

  async fetchStats() {
    try {
      const statsRes = await fetch("http://localhost:5000/api/dashboard/stats");
      const stats = await statsRes.json();

      const analRes = await fetch("http://localhost:5000/api/admin/analytics");
      const analytics = await analRes.json();

      return { ...stats, analytics };
    } catch (error) {
      console.error("Error fetching stats:", error);
      return {};
    }
  }

  handleScroll() {
    const nav = document.querySelector("nav");
    const scrollY = window.scrollY;
    const docHeight =
      document.documentElement.scrollHeight - window.innerHeight;
    const scrollPercent = Math.min(Math.max(scrollY / docHeight, 0), 1);
    const progress = scrollPercent * 10000;

    if (nav) {
      if (scrollY > 50) {
        nav.classList.add("glass-nav");
      } else {
        nav.classList.remove("glass-nav");
      }
    }

    // Update Network Line and Pulse Node
    const path = document.querySelector(".network-path");
    const node = document.querySelector(".network-pulse-node");

    if (path) {
      const totalLength = path.getTotalLength();
      // Scale progress to the actual path length
      path.style.strokeDasharray = totalLength;
      path.style.strokeDashoffset = totalLength - scrollPercent * totalLength;

      if (node) {
        const point = path.getPointAtLength(scrollPercent * totalLength);
        node.setAttribute("cx", point.x);
        node.setAttribute("cy", point.y);
      }
    }
  }

  initScrollAnimations() {
    const observerOptions = {
      threshold: 0.1,
      rootMargin: "0px 0px -50px 0px",
    };

    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("active");
        }
      });
    }, observerOptions);

    const revealElements = document.querySelectorAll(".reveal");
    revealElements.forEach((el) => observer.observe(el));
  }

  startCarousel() {
    const slides = document.querySelectorAll(".carousel-slide");
    if (slides.length === 0) return;

    let currentSlide = 0;

    const nextSlide = () => {
      slides[currentSlide].classList.remove("active");
      currentSlide = (currentSlide + 1) % slides.length;
      slides[currentSlide].classList.add("active");
    };

    if (this.carouselInterval) clearInterval(this.carouselInterval);
    this.carouselInterval = setInterval(nextSlide, 5000); // Change image every 5 seconds
  }

  animateCounters() {
    const counters = document.querySelectorAll(".counter");
    counters.forEach((counter) => {
      const target = parseInt(counter.innerText);
      let count = 0;
      const speed = 2000 / target;

      const updateCount = () => {
        if (count < target) {
          count++;
          counter.innerText =
            count + (counter.innerText.includes("+") ? "+" : "");
          setTimeout(updateCount, speed);
        } else {
          counter.innerText =
            target + (counter.innerText.includes("+") ? "+" : "");
        }
      };

      updateCount();
    });
  }
  openCertificateModal(eventId) {
    const modal = document.getElementById("certificateModal");
    if (!modal) return;
    document.getElementById("certEventId").value = eventId;
    modal.style.display = "flex";
    setTimeout(() => modal.classList.add("active"), 10);
  }

  closeCertificateModal() {
    const modal = document.getElementById("certificateModal");
    if (!modal) return;
    modal.classList.remove("active");
    setTimeout(() => (modal.style.display = "none"), 300);
  }

  async handleReleaseCertificates(event) {
    event.preventDefault();
    const eventId = document.getElementById("certEventId").value;
    const formData = new FormData(event.target);
    const btn = event.submitter;
    const originalText = btn.innerText;

    btn.innerText = "⏳ Processing...";
    btn.disabled = true;

    try {
      const response = await fetch(
        `http://localhost:5000/api/events/${eventId}/certificates`,
        {
          method: "POST",
          body: formData,
        },
      );

      const result = await response.json();

      if (response.ok) {
        alert("Success: " + result.message);
        this.closeCertificateModal();
      } else {
        alert("Failed: " + result.message);
      }
    } catch (error) {
      console.error(error);
      alert("Error connecting to server.");
    } finally {
      btn.innerText = originalText;
      btn.disabled = false;
    }
  }
}

new App();

// Handle browser back/forward buttons
window.onpopstate = () => {
  window.app.render();
};
