import geoip from 'geoip-lite';

// Update the geo database
console.log('🌍 Updating GeoIP database...');
geoip.reloadData();
console.log('✅ GeoIP update complete!');