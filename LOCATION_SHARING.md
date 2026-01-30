# Location Sharing Feature

## Implementation

### Backend (Go)
- Added `latitude` and `longitude` fields to Message struct
- Updated database schema to include location columns
- Modified message INSERT queries to save location data
- Updated SELECT queries to retrieve location data

### Frontend (JavaScript)
- Add button to share location
- Use HTML5 Geolocation API
- Display location as Google Maps link or map preview

### Usage
1. Click location button (📍) in chat input area
2. Browser will request permission to access location
3. Location will be sent as message with coordinates
4. Recipient can click to view on map
