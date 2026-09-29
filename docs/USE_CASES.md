# Use Cases

## UC-1: User Login
**Actor:** Investigator
**Precondition:** User has valid credentials
**Steps:**
1. User navigates to login page
2. User enters username and password
3. System validates credentials
4. User is redirected to dashboard

## UC-2: Create Investigation Case
**Actor:** Investigator
**Precondition:** User is authenticated
**Steps:**
1. User clicks "New Case"
2. User enters case name and description
3. System creates case record
4. User is redirected to case detail page

## UC-3: Upload Evidence
**Actor:** Investigator
**Precondition:** Case exists
**Steps:**
1. User navigates to evidence section
2. User selects file to upload
3. System uploads and parses file
4. System stores events in database
5. User receives confirmation

## UC-4: View Timeline
**Actor:** Investigator
**Precondition:** Case has events
**Steps:**
1. User navigates to timeline view
2. System displays events chronologically
3. User can zoom and filter
4. User can click events for details

## UC-5: Generate Report
**Actor:** Investigator
**Precondition:** Case has analysis results
**Steps:**
1. User clicks "Generate Report"
2. User selects report options
3. System compiles report
4. User downloads report
