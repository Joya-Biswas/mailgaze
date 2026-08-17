# Mailgaze Documentation Index

Complete documentation for the Mailgaze email header forensics application.

---

## 📚 Documentation Files

### 1. **README.md** — Start Here
- Quick overview
- Why Mailgaze exists
- Installation steps
- Basic usage
- Tech stack
- **Read this first!**

### 2. **GUIDE.md** — Complete Beginner's Guide (Most Comprehensive)
**Best for**: Understanding everything about the project

**Contains**:
- What is Mailgaze (with context on email headers)
- Complete project structure
- How I built it (design decisions)
- Step-by-step data flow
- Module reference (every function documented)
- All 20 detection rules explained (R1–R20)
- Using the application (workflows)
- How to extend it (add rules, fields, routes)
- Troubleshooting
- FAQ

**Length**: ~10,000 words  
**Read time**: 45–60 minutes  
**Sections**: 10

### 3. **ARCHITECTURE.md** — Technical Deep Dive
**Best for**: Understanding the internals, design patterns, and system flows

**Contains**:
- System architecture diagram
- Data flow diagrams (for each major operation)
- Module dependency graph
- Detailed parser flow
- Analyzer rule application flow
- GeoIP module design
- Explainer module
- HTTP request/response cycle
- Template rendering
- Error handling strategy
- Performance considerations
- Security considerations
- Testing strategy
- Deployment architecture
- Decision log (why certain choices)

**Length**: ~5,000 words  
**Read time**: 30–40 minutes  
**Diagrams**: 15+

### 4. **QUICK_REFERENCE.md** — Cheat Sheet & Common Tasks
**Best for**: Quick answers, copy-paste code, common modifications

**Contains**:
- Installation & setup (one-liners)
- Common tasks (add rule, add field, add route, customize verdict, etc.)
- Troubleshooting (quick fixes for common errors)
- File locations reference
- Code snippets (ready to use)
- Performance tips
- Deployment checklists
- Version history & roadmap
- Getting help

**Length**: ~3,000 words  
**Read time**: 10–20 minutes  
**Code snippets**: 20+

---

## 🎯 Which Document Should I Read?

### "I want to understand what Mailgaze is"
→ **README.md** (5 min) + **GUIDE.md sections 1–2** (10 min)

### "I want to understand how it works"
→ **GUIDE.md sections 3–5** (20 min)

### "I want to understand every module"
→ **GUIDE.md section 5** (detailed module reference)

### "I want to understand the detection rules"
→ **GUIDE.md section 6** (all 20 rules explained)

### "I want to add a new rule"
→ **QUICK_REFERENCE.md** "Add a new detection rule" (copy-paste)

### "I want to understand system design"
→ **ARCHITECTURE.md** (data flows, diagrams)

### "I want to customize the UI colors"
→ **QUICK_REFERENCE.md** "Change colors in the UI"

### "I want to troubleshoot an error"
→ **QUICK_REFERENCE.md** "Troubleshooting"

### "I want to deploy to production"
→ **ARCHITECTURE.md** "Deployment Architecture" + **QUICK_REFERENCE.md** "Deployment Checklists"

---

## 📋 Reading Paths

### Path 1: Beginner Getting Started (30 minutes)
1. README.md (5 min) — What is it?
2. GUIDE.md section 1 (5 min) — What is Mailgaze?
3. Installation & run the server (10 min)
4. Try both sample emails (5 min)
5. GUIDE.md section 7 (5 min) — How to use it

### Path 2: Developer Learning the Codebase (2 hours)
1. README.md (5 min)
2. GUIDE.md sections 1–5 (40 min) — Design, structure, modules
3. GUIDE.md section 6 (20 min) — Detection rules
4. ARCHITECTURE.md sections 1–3 (30 min) — Data flows, design
5. Run tests: `pytest tests/ -v` (5 min)
6. Read one module source code (15 min)
7. QUICK_REFERENCE.md (5 min) — Common tasks

### Path 3: Developer Extending the App (1 hour)
1. GUIDE.md section 8 — How to extend
2. QUICK_REFERENCE.md section "Common Tasks" — Pick a task
3. Implement the change
4. Test: `pytest tests/` or `python run.py`
5. Repeat

### Path 4: Ops/DevOps Deploying to Production (30 minutes)
1. README.md sections "Tech stack" and "Install"
2. ARCHITECTURE.md "Deployment Architecture"
3. QUICK_REFERENCE.md "Deployment Checklists"
4. Docker setup or cloud platform setup
5. Test on production environment

---

## 📖 Document Structure

### README.md
```
- Tagline
- What it does
- Why it exists
- Architecture diagram
- Tech stack
- Install / Run
- Usage
- Testing
- Roadmap
- License
```

### GUIDE.md
```
1. What is Mailgaze?
2. Project Structure
3. How I Built It
4. How It Works: Step by Step
5. Module Reference (detailed)
6. Detection Rules (R1–R20)
7. Using the Application
8. Extending Mailgaze
9. Troubleshooting
10. FAQ
```

### ARCHITECTURE.md
```
1. System Architecture Overview
2. Data Flow Diagram
3. Module Dependency Graph
4. Parser Module Data Flow
5. Analyzer Module Data Flow
6. GeoIP Module Design
7. Explainer Module
8. HTTP Request/Response Cycle
9. Template Rendering
10. Error Handling Strategy
11. Performance Considerations
12. Security Considerations
13. Testing Strategy
14. Deployment Architecture
15. Module Responsibilities
16. Decision Log
17. Conclusion
```

### QUICK_REFERENCE.md
```
- Installation & Setup
- Common Tasks (10 examples)
- Troubleshooting (8 common errors)
- File Locations Reference
- Code Snippets (ready to copy-paste)
- Performance Tips
- Deployment Checklists
- Version History & Roadmap
- Getting Help
```

---

## 🔍 Quick Links Within Documents

### In GUIDE.md:
- Detection rule R1 → Section 6, subsection "Rule R1"
- How to use → Section 7
- Add a new rule → Section 8, subsection "Adding a New Detection Rule"
- Troubleshooting → Section 9

### In ARCHITECTURE.md:
- Data flow for analyzing an email → Section 2
- Parser details → Section 4
- Error handling → Section 10
- Deployment → Section 14

### In QUICK_REFERENCE.md:
- Add a rule → "Common Tasks", first item
- Port already in use error → "Troubleshooting", first item
- Docker deployment → "Deployment Checklists"

---

## 📊 Documentation Statistics

| Document | Length | Read Time | Content Type |
|----------|--------|-----------|---|
| README.md | ~2,000 words | 10 min | Overview |
| GUIDE.md | ~10,000 words | 50 min | Complete guide |
| ARCHITECTURE.md | ~5,000 words | 30 min | Technical |
| QUICK_REFERENCE.md | ~3,000 words | 15 min | Reference |
| **TOTAL** | **~20,000 words** | **2+ hours** | — |

---

## 🎓 Learning Outcomes

After reading these docs, you will understand:

### After README.md:
- ✓ What Mailgaze does
- ✓ Why it was built
- ✓ How to install and run it

### After GUIDE.md:
- ✓ How email headers work
- ✓ Every module's responsibility
- ✓ All 20 detection rules
- ✓ How the analysis pipeline works
- ✓ How to extend the app
- ✓ Common troubleshooting

### After ARCHITECTURE.md:
- ✓ System architecture and design patterns
- ✓ Data flow through the app
- ✓ Module dependencies
- ✓ Error handling strategy
- ✓ Why certain design decisions were made
- ✓ How to deploy to production

### After QUICK_REFERENCE.md:
- ✓ Common tasks and how to do them
- ✓ Where to find everything
- ✓ Code snippets for common operations
- ✓ How to debug common problems

---

## 🛠️ How to Use This Documentation

### For Questions About:

| Question | Go To | Section |
|----------|-------|---------|
| What is Mailgaze? | README.md | Intro |
| How do I install it? | README.md or QUICK_REFERENCE.md | "Install" |
| How does it work? | GUIDE.md | Section 4 |
| What does module X do? | GUIDE.md | Section 5 |
| What is detection rule R5? | GUIDE.md | Section 6 |
| How do I use it? | GUIDE.md | Section 7 |
| How do I add a rule? | QUICK_REFERENCE.md | "Add a new detection rule" |
| Why is there an error? | QUICK_REFERENCE.md | "Troubleshooting" |
| How is it deployed? | ARCHITECTURE.md | "Deployment Architecture" |
| What are the design decisions? | ARCHITECTURE.md | "Decision Log" |

---

## 📞 Getting More Help

### If you can't find an answer:

1. **Check QUICK_REFERENCE.md** → "Getting Help" section
2. **Search GUIDE.md** for keywords (Ctrl+F)
3. **Search ARCHITECTURE.md** for technical details
4. **Open an issue** on GitHub with:
   - Python version: `python --version`
   - Error message (exact)
   - Steps to reproduce
   - Which doc you checked

---

## 🚀 Next Steps

### If you're new to Mailgaze:
1. Read **README.md** (5 min)
2. Install and run (10 min)
3. Try the samples (5 min)
4. Read **GUIDE.md** sections 1–2 (10 min)

### If you want to contribute:
1. Fork the repo
2. Read **GUIDE.md** section 8 (extending)
3. Read **ARCHITECTURE.md** (understand the design)
4. Make your changes
5. Run **`pytest tests/`**
6. Submit a pull request

### If you want to deploy:
1. Read **QUICK_REFERENCE.md** "Deployment Checklists"
2. Read **ARCHITECTURE.md** "Deployment Architecture"
3. Choose your platform (Docker, Heroku, AWS, etc.)
4. Deploy!

---

## 📝 Document Maintenance

These docs are accurate as of **v0.1.0**.

If you:
- **Add a new rule**: Update GUIDE.md section 6
- **Add a new module**: Update GUIDE.md section 5 + ARCHITECTURE.md
- **Change verdict logic**: Update GUIDE.md section 6 + QUICK_REFERENCE.md
- **Add a deployment option**: Update ARCHITECTURE.md "Deployment Architecture"

---

## 💡 Tips for Reading

1. **Don't read linearly**: Jump to what you need
2. **Use Ctrl+F**: Search within each document
3. **Read GUIDE.md once**: Gives context; easier to understand later docs
4. **Refer to QUICK_REFERENCE.md often**: It's designed for quick lookups
5. **Run the code**: Reading code is better with a running server to reference

---

## 📚 Additional Resources

- **Python**: https://docs.python.org/3.11/
- **FastAPI**: https://fastapi.tiangolo.com/
- **Email headers**: https://tools.ietf.org/html/rfc5322
- **SPF/DKIM/DMARC**: https://tools.ietf.org/html/rfc7208, rfc6376, rfc7489
- **Phishing awareness**: https://www.cisa.gov/phishing (US Govt guide)

---

## 🎉 Summary

You have **4 complete documentation files** totaling **~20,000 words**:

1. **README.md** — Quick start
2. **GUIDE.md** — Everything explained
3. **ARCHITECTURE.md** — Technical details
4. **QUICK_REFERENCE.md** — Cheat sheet

Pick the one(s) that match your needs, and start learning!

**Happy exploring!** 🔍

