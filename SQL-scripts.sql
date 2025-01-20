
-- Create table for DPI sessions --
CREATE TABLE raw_data.dpi_sessions (
    session_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    start_time DATETIME NOT NULL,
    end_time DATETIME NOT NULL,
    base_station_id INT NOT NULL,
    latitude DECIMAL(10, 6) NOT NULL,
    longitude DECIMAL(10, 6) NOT NULL,
    user_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45) NOT NULL,
    domain VARCHAR(255),
    protocol VARCHAR(10),
    port INT,
    traffic_volume BIGINT,
    traffic_direction ENUM('upload', 'download'),
    packet_count INT,
    avg_packet_size DECIMAL(10, 2),
    duration INT,
    country VARCHAR(100),
    region VARCHAR(100),
    city VARCHAR(100),
    asn INT,
    isp VARCHAR(100),
    user_id BIGINT,
    subscriber_id BIGINT,
    msisdn VARCHAR(15),
    device_type VARCHAR(50),
    os VARCHAR(50),
    browser VARCHAR(50),
    user_agent TEXT,
    application_name VARCHAR(100),
    content_type VARCHAR(50),
    risk_category ENUM('safe', 'suspicious', 'malicious'),
    category VARCHAR(50),
    is_vpn BOOLEAN,
    connection_type ENUM('4G', '5G', 'Wi-Fi'),
    throttled BOOLEAN,
    error_code INT
);
-- Traffic Analysis by Time of Day--
SELECT 
    CASE
        WHEN HOUR(start_time) BETWEEN 6 AND 11 THEN 'Morning'
        WHEN HOUR(start_time) BETWEEN 12 AND 17 THEN 'Afternoon'
        WHEN HOUR(start_time) BETWEEN 18 AND 23 THEN 'Evening'
        ELSE 'Night'
    END AS time_of_day,
    SUM(traffic_volume) AS total_traffic
FROM raw_data.dpi_sessions
GROUP BY time_of_day
ORDER BY total_traffic DESC;

-- Top 10 Domains by Traffic Volume --

SELECT 
    domain,
    SUM(traffic_volume) AS total_traffic
FROM raw_data.dpi_sessions
WHERE domain IS NOT NULL
GROUP BY domain
ORDER BY total_traffic DESC
LIMIT 10;

-- Average Packet Size by Connection Type --
SELECT 
    connection_type,
    AVG(avg_packet_size) AS average_packet_size
FROM raw_data.dpi_sessions
GROUP BY connection_type;

--- Traffic by Country ---

SELECT 
    country,
    SUM(traffic_volume) AS total_traffic,
    COUNT(DISTINCT user_id) AS unique_users
FROM raw_data.dpi_sessions
GROUP BY country
ORDER BY total_traffic DESC;

-- Top 10 Suspicious or Malicious Destination IPs --

SELECT 
    destination_ip,
    SUM(traffic_volume) AS total_traffic,
    COUNT(*) AS session_count
FROM raw_data.dpi_sessions
WHERE risk_category IN ('suspicious', 'malicious')
GROUP BY destination_ip
ORDER BY total_traffic DESC
LIMIT 10;

-- Index Creation for Performance Optimization --
CREATE INDEX idx_start_time_risk_category
ON raw_data.dpi_sessions (start_time, risk_category);

--  Average Session Duration--
SELECT 
    device_type,
    AVG(duration) AS avg_session_duration
FROM raw_data.dpi_sessions
GROUP BY device_type;

-- Traffic Through VPN --
SELECT 
    (SUM(CASE WHEN is_vpn = TRUE THEN traffic_volume ELSE 0 END) / SUM(traffic_volume)) * 100 AS vpn_traffic_percentage
FROM raw_data.dpi_sessions;

-- Errors by Connection Type --
SELECT 
    connection_type,
    COUNT(error_code) AS error_count
FROM raw_data.dpi_sessions
WHERE error_code IS NOT NULL
GROUP BY connection_type
ORDER BY error_count DESC;

-- Peak Traffic Detection --
SELECT 
    DATE_FORMAT(start_time, '%Y-%m-%d %H:00:00') AS hourly_interval,
    SUM(traffic_volume) AS total_traffic
FROM raw_data.dpi_sessions
GROUP BY hourly_interval
ORDER BY total_traffic DESC
LIMIT 10;
