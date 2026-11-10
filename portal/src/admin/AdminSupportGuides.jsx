import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import './AdminSupportGuides.css'

export default function AdminSupportGuides({ admin, user }) {
  const navigate = useNavigate()
  const [activeCategory, setActiveCategory] = useState('boot')
  const [callerName, setCallerName] = useState('')
  const [callerNotes, setCallerNotes] = useState('')
  const [completedSteps, setCompletedSteps] = useState({})

  const toggleStep = (stepId) => {
    setCompletedSteps(prev => ({
      ...prev,
      [stepId]: !prev[stepId]
    }))
  }

  const handleSendToTerminal = (presetId, customDesc = '') => {
    navigate('/admin/terminal', {
      state: {
        preset: presetId,
        customerName: callerName,
        customDesc: customDesc || undefined
      }
    })
  }

  const GUIDES = {
    boot: {
      title: 'Boot & System Crash Diagnostics',
      icon: '💻',
      urgency: 'HIGH',
      recommendedPreset: 'tuneup',
      recommendedPresetName: 'Deep PC/Mac Tune-Up ($100 flat)',
      openingScript: "I understand your system won't boot properly. Don't worry—most boot failures are software or filesystem hiccups that we can recover without losing your data.",
      questions: [
        { id: 'b1', q: 'Does the power button illuminate or make any fan noises when pressed?' },
        { id: 'b2', q: 'Are you seeing a Blue Screen of Death (BSOD) with an error code like CRITICAL_PROCESS_DIED or INACCESSIBLE_BOOT_DEVICE?' },
        { id: 'b3', q: 'Does the machine turn on but freeze on the manufacturer logo (Dell, HP, Apple, Lenovo) with a spinning dot loop?' },
        { id: 'b4', q: 'Is there a BitLocker recovery key screen prompting for a 48-digit numerical key?' },
        { id: 'b5', q: 'Did the computer recently complete a major Windows/macOS update right before this started?' }
      ],
      triageSteps: [
        {
          id: 'step_b1',
          title: 'Hard Power Cycle & Static Discharge',
          details: 'Unplug power cable (or battery if removable). Hold power button down continuously for 30 full seconds. Reconnect AC power directly to wall socket (bypass power strip) and power on.'
        },
        {
          id: 'step_b2',
          title: 'Safe Mode / Recovery Environment Access',
          details: 'For Windows: Power off hard 3 times consecutively during boot to trigger Automatic Repair. Select Troubleshoot → Advanced Options → Startup Settings → Restart → Press 4 for Safe Mode with Networking.'
        },
        {
          id: 'step_b3',
          title: 'Command Line Integrity Check',
          details: 'In Recovery Command Prompt: Run "chkdsk C: /f /r" to repair bad sectors, followed by "sfc /scannow /offbootdir=c:\\ /offwindir=c:\\windows".'
        },
        {
          id: 'step_b4',
          title: 'BitLocker Key Retrieval',
          details: 'Instruct caller to access aka.ms/myrecoverykey on their smartphone using their Microsoft account credentials to retrieve the 48-digit numerical recovery key.'
        }
      ]
    },

    printer: {
      title: 'Printer & Peripheral Dispatch',
      icon: '🖨️',
      urgency: 'STANDARD',
      recommendedPreset: 'hourly',
      recommendedPresetName: 'Hourly Remote Support ($150/hr - 1 hr)',
      openingScript: "Printers frequently drop offline due to IP lease changes or stuck spooler jobs. Let's run a rapid connection test.",
      questions: [
        { id: 'p1', q: 'Is the printer connected via USB cable directly, or wireless Wi-Fi / Ethernet cable?' },
        { id: 'p2', q: 'Does the printer show an IP address on its front touchscreen or network test page?' },
        { id: 'p3', q: 'Are there stuck documents in the print queue marked with "Error - Printing"?' },
        { id: 'p4', q: 'Can other computers or phones in the office print to this machine right now?' }
      ],
      triageSteps: [
        {
          id: 'step_p1',
          title: 'Restart Windows Print Spooler Service',
          details: 'Open cmd as Admin. Execute: "net stop spooler && del /Q /F /S %systemroot%\\System32\\Spool\\Printers\\* && net start spooler". This immediately drains stuck print jobs.'
        },
        {
          id: 'step_p2',
          title: 'Verify Local IP Reachability',
          details: 'From technician or customer PC, run "ping [Printer_IP]". If ping replies with request timed out, power-cycle the printer and router.'
        },
        {
          id: 'step_p3',
          title: 'Re-add via Static TCP/IP Port',
          details: 'Open Printers & Scanners → Add Printer → "The printer that I want isn\'t listed" → Add using TCP/IP address. Set a reserved static IP on the router.'
        }
      ]
    },

    network: {
      title: 'Wi-Fi & Network Outage Protocol',
      icon: '📶',
      urgency: 'HIGH',
      recommendedPreset: 'network',
      recommendedPresetName: 'Home Network & Wi-Fi Optimization ($150 flat)',
      openingScript: "Let's check whether this is an ISP upstream blackout or a local wireless gateway / DNS resolution issue.",
      questions: [
        { id: 'n1', q: 'Is the WAN / Internet light on the modem/ONT solid green/white, or blinking red/amber?' },
        { id: 'n2', q: 'Does the computer show "Connected, no internet access" or "Can\'t connect to this network"?' },
        { id: 'n3', q: 'Are other smartphones or tablets able to load web pages on the same Wi-Fi?' },
        { id: 'n4', q: 'Is a third-party VPN (Nord, Express, Surfshark) or third-party antivirus firewall running?' }
      ],
      triageSteps: [
        {
          id: 'step_n1',
          title: 'Modem & Router Sequential Cold Boot',
          details: 'Unplug power to both ONT/modem and Wi-Fi router. Wait 60 seconds. Plug modem in first and wait for sync lights (2-3 min). Then power up main router.'
        },
        {
          id: 'step_n2',
          title: 'Flush DNS & Reset Winsock Stack',
          details: 'Open Admin Command Prompt. Run: "ipconfig /flushdns", "netsh winsock reset", "netsh int ip reset", followed by a system reboot.'
        },
        {
          id: 'step_n3',
          title: 'Configure Public High-Availability DNS',
          details: 'Set IPv4 DNS to Cloudflare primary 1.1.1.1 and Google secondary 8.8.8.8. This resolves local ISP DNS outages immediately.'
        }
      ]
    },

    malware: {
      title: 'Malware, Scams & Locked Browser Alerts',
      icon: '🦠',
      urgency: 'CRITICAL',
      recommendedPreset: 'tuneup',
      recommendedPresetName: 'Deep PC/Mac Tune-Up & Malware Removal ($100 flat)',
      openingScript: "DO NOT call any telephone numbers displayed on your screen! That is a fraudulent pop-up designed to look like Microsoft or Apple. Your data is safe—do not give them remote access.",
      questions: [
        { id: 'm1', q: 'Is a loud siren or synthesized robotic voice playing saying your computer is compromised?' },
        { id: 'm2', q: 'Did the caller already grant remote control to someone claiming to be Microsoft or Amazon?' },
        { id: 'm3', q: 'Did the customer give any bank details, gift card numbers, or passwords to anyone?' },
        { id: 'm4', q: 'Is the screen locked in full screen where the cursor or close (X) button is hidden?' }
      ],
      triageSteps: [
        {
          id: 'step_m1',
          title: 'Immediately Disconnect from Internet',
          details: 'Instruct caller to immediately switch off Wi-Fi or unplug the blue Ethernet cable from the computer. This severs any backdoor access.'
        },
        {
          id: 'step_m2',
          title: 'Kill Trapped Browser Process',
          details: 'Press Ctrl + Shift + Esc to launch Task Manager (or Command + Option + Esc on Mac). Force kill "chrome.exe", "msedge.exe", or "safari".'
        },
        {
          id: 'step_m3',
          title: 'Remove Fraudulent Remote Tools',
          details: 'Inspect installed apps for AnyDesk, TeamViewer, UltraViewer, or ScreenConnect installed within the last 24 hours and uninstall immediately.'
        },
        {
          id: 'step_m4',
          title: 'Offline Malwarebytes / Antivirus Remediation',
          details: 'Run full deep rootkit scan and clear browser cache and notification permissions in Edge/Chrome Settings → Site Permissions → Notifications.'
        }
      ]
    },

    email: {
      title: 'Email, M365 & Account Lockouts',
      icon: '📧',
      urgency: 'MEDIUM',
      recommendedPreset: 'hourly',
      recommendedPresetName: 'Hourly IT Support ($150/hr - 1 hr)',
      openingScript: "We can help you re-authenticate and restore your mailbox access while keeping your account security intact.",
      questions: [
        { id: 'e1', q: 'Is the account a corporate Microsoft 365 / Google Workspace or a personal consumer email?' },
        { id: 'e2', q: 'Are you locked out due to forgotten password, expired credentials, or 2FA Authenticator loop?' },
        { id: 'e3', q: 'Can you sign in successfully via webmail (outlook.office.com or mail.google.com) on a phone browser?' },
        { id: 'e4', q: 'Is the desktop Outlook client showing "Need Password" or "Disconnected" in the bottom status bar?' }
      ],
      triageSteps: [
        {
          id: 'step_e1',
          title: 'Clear Stale Windows Credential Manager Entries',
          details: 'Open Control Panel → Credential Manager → Windows Credentials. Delete all generic credentials starting with "MicrosoftOffice16_Data:" or "OneDrive:".'
        },
        {
          id: 'step_e2',
          title: 'Re-authenticate with Modern Auth',
          details: 'Open Settings → Accounts → Access work or school. If the account shows a "Fix account" warning, click Fix and prompt user for MFA push notification.'
        },
        {
          id: 'step_e3',
          title: 'Rebuild Outlook Mail Profile',
          details: 'Open Control Panel → Mail (Microsoft Outlook) → Show Profiles → Add new profile "LANZAR_Clean". Autodiscover will pull down modern cached mail.'
        }
      ]
    }
  }

  const currentGuide = GUIDES[activeCategory]

  return (
    <div className="guides-container">
      {/* Header */}
      <div className="guides-header">
        <div>
          <span className="guides-badge">TECH SUPPORT OPERATIONS</span>
          <h1 className="guides-title">INTERACTIVE TRIAGE &amp; DIAGNOSTIC PLAYBOOK</h1>
          <p className="guides-sub">
            Standard Operating Procedures, customer scripts, and rapid diagnostic workflows for phone technicians.
          </p>
        </div>
        <button 
          type="button" 
          className="btn-quick-terminal"
          onClick={() => handleSendToTerminal('hourly', 'On-Demand IT Diagnostic Support')}
        >
          💳 Open Virtual Terminal ↗
        </button>
      </div>

      {/* Technician Caller Sticky Bar */}
      <div className="caller-session-bar">
        <div className="session-col">
          <label className="session-label">CALLER NAME:</label>
          <input 
            type="text" 
            className="session-input" 
            placeholder="e.g. John Doe / Acme Corp" 
            value={callerName} 
            onChange={(e) => setCallerName(e.target.value)} 
          />
        </div>
        <div className="session-col" style={{ flex: 2 }}>
          <label className="session-label">CALL NOTES &amp; SYMPTOMS:</label>
          <input 
            type="text" 
            className="session-input" 
            placeholder="e.g. Customer heard 3 beeps, smells hot plastic, PC shut off during Excel" 
            value={callerNotes} 
            onChange={(e) => setCallerNotes(e.target.value)} 
          />
        </div>
        <div className="session-col-btn">
          <button 
            type="button" 
            className="btn-dispatch-charge"
            onClick={() => handleSendToTerminal(currentGuide.recommendedPreset, `${currentGuide.title} - ${callerNotes || 'Diagnosed on call'}`)}
          >
            BILL THIS SERVICE (${`$${currentGuide.recommendedPresetName.split('$')[1] || 'Over Phone)'}`} ↗
          </button>
        </div>
      </div>

      {/* Category Tabs */}
      <div className="guides-tabs">
        {Object.entries(GUIDES).map(([key, item]) => (
          <button
            key={key}
            type="button"
            className={`guide-tab-btn ${activeCategory === key ? 'active' : ''}`}
            onClick={() => setActiveCategory(key)}
          >
            <span className="tab-icon">{item.icon}</span>
            <span className="tab-title">{item.title.split('&')[0].trim()}</span>
          </button>
        ))}
      </div>

      {/* Guide Content Deck */}
      <div className="guide-content-grid">
        
        {/* Left Column: Script & Questions */}
        <div className="guide-panel">
          
          <div className="panel-header">
            <span className="guide-urgency-tag">{currentGuide.urgency} SEVERITY</span>
            <h2>{currentGuide.icon} {currentGuide.title}</h2>
          </div>

          {/* Caller Script Box */}
          <div className="script-card">
            <span className="script-label">🗣️ SUGGESTED CALLER OPENING / REASSURANCE:</span>
            <p className="script-quote">"{currentGuide.openingScript}"</p>
          </div>

          {/* Diagnostic Triage Questions */}
          <div className="questions-section">
            <h3 className="section-heading">🔍 TRIAGE CHECKLIST (ASK CALLER):</h3>
            <div className="checklist-items">
              {currentGuide.questions.map((item) => (
                <label 
                  key={item.id} 
                  className={`check-item ${completedSteps[item.id] ? 'checked' : ''}`}
                >
                  <input 
                    type="checkbox" 
                    checked={!!completedSteps[item.id]} 
                    onChange={() => toggleStep(item.id)} 
                  />
                  <span className="check-text">{item.q}</span>
                </label>
              ))}
            </div>
          </div>

        </div>

        {/* Right Column: SOP Protocol & Virtual Terminal Dispatch */}
        <div className="guide-panel">
          
          <div className="panel-header">
            <h2>🛠️ RESOLUTION PROTOCOL (STEP-BY-STEP)</h2>
          </div>

          <div className="protocol-steps">
            {currentGuide.triageSteps.map((step, idx) => (
              <div key={step.id} className="protocol-step-card">
                <div className="step-num">{idx + 1}</div>
                <div className="step-body">
                  <h4>{step.title}</h4>
                  <p>{step.details}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Dispatch Action Box */}
          <div className="dispatch-action-card">
            <div className="dispatch-action-info">
              <span className="dispatch-tag">RECOMMENDED BILLING TIER</span>
              <div className="dispatch-title">{currentGuide.recommendedPresetName}</div>
              <p className="dispatch-desc">
                Instantly transfer caller details into the Virtual Terminal to authorize payment over the phone or email a Stripe link.
              </p>
            </div>
            <button 
              type="button" 
              className="btn-charge-now" 
              onClick={() => handleSendToTerminal(currentGuide.recommendedPreset, `${currentGuide.title} - ${callerNotes || 'Diagnosed on call'}`)}
            >
              PROCEED TO PAYMENT TERMINAL ↗
            </button>
          </div>

        </div>

      </div>

    </div>
  )
}
