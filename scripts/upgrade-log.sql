# Updates log table to new format... Only needed if upgrading from 
# Blackhole <= 1.0.7
ALTER TABLE log CHANGE entry hostname VARCHAR(255);
ALTER TABLE log ADD (
		status VARCHAR(50) DEFAULT NULL,
		score FLOAT DEFAULT NULL,
		size BIGINT(20) DEFAULT NULL,
		relay VARCHAR(255) DEFAULT NULL,
		sender VARCHAR(255) DEFAULT NULL,
		recipient VARCHAR(255) DEFAULT NULL
);
		
