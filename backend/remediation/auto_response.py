"""
Automated Remediation Module
Simulates or executes automated response actions for detected threats
"""

import os
from datetime import datetime, timedelta
from config import Config
from database.models import BlockedIP, RemediationAction, ThreatEvent
from database.db import db
from utils.logger import log_to_database

class AutoRemediation:
    def __init__(self, simulation_mode=None):
        if simulation_mode is None:
            self.simulation_mode = Config.SIMULATION_MODE
        else:
            self.simulation_mode = simulation_mode
    
    def block_ip(self, ip_address, reason, duration_minutes=60):
        """Block an IP address (simulated or real)"""
        action_type = 'ip_block'
        
        if self.simulation_mode:
            # Simulated action
            result = {
                'success': True,
                'action': 'simulated_ip_block',
                'ip': ip_address,
                'reason': reason,
                'message': f'[SIMULATED] IP {ip_address} would be blocked for {duration_minutes} minutes'
            }
            log_to_database('INFO', 'AutoRemediation', 
                          f"Simulated blocking IP: {ip_address} - {reason}")
        else:
            # Real action (would execute actual firewall commands)
            # In production, this would integrate with iptables, firewalld, etc.
            result = {
                'success': True,
                'action': 'ip_block',
                'ip': ip_address,
                'reason': reason,
                'message': f'IP {ip_address} blocked successfully'
            }
            log_to_database('WARNING', 'AutoRemediation', 
                          f"Blocking IP: {ip_address} - {reason}")
        
        # Save to database
        blocked_ip = BlockedIP(
            ip_address=ip_address,
            reason=reason,
            blocked_until=datetime.utcnow() + timedelta(minutes=duration_minutes),
            is_active=True
        )
        db.session.add(blocked_ip)
        
        # Record remediation action
        remediation = RemediationAction(
            action_type=action_type,
            target=ip_address,
            status='completed',
            details=reason,
            simulation_mode=self.simulation_mode
        )
        db.session.add(remediation)
        db.session.commit()
        
        return result
    
    def unblock_ip(self, ip_address):
        """Unblock a previously blocked IP"""
        action_type = 'ip_unblock'
        
        blocked = BlockedIP.query.filter_by(ip_address=ip_address, is_active=True).first()
        if blocked:
            blocked.is_active = False
            blocked.blocked_until = datetime.utcnow()
            
            if self.simulation_mode:
                message = f'[SIMULATED] IP {ip_address} would be unblocked'
            else:
                message = f'IP {ip_address} unblocked'
            
            remediation = RemediationAction(
                action_type=action_type,
                target=ip_address,
                status='completed',
                details='Manual unblock',
                simulation_mode=self.simulation_mode
            )
            db.session.add(remediation)
            db.session.commit()
            
            log_to_database('INFO', 'AutoRemediation', message)
            return {'success': True, 'message': message}
        
        return {'success': False, 'message': 'IP not found in blocked list'}
    
    def lock_account(self, username, reason):
        """Lock a user account (simulated)"""
        action_type = 'account_lock'
        
        if self.simulation_mode:
            result = {
                'success': True,
                'action': 'simulated_account_lock',
                'account': username,
                'message': f'[SIMULATED] Account {username} would be locked: {reason}'
            }
        else:
            # In production, would integrate with LDAP/AD/local auth system
            result = {
                'success': True,
                'action': 'account_lock',
                'account': username,
                'message': f'Account {username} locked'
            }
        
        remediation = RemediationAction(
            action_type=action_type,
            target=username,
            status='completed',
            details=reason,
            simulation_mode=self.simulation_mode
        )
        db.session.add(remediation)
        db.session.commit()
        
        log_to_database('WARNING', 'AutoRemediation', 
                       f"Account locked: {username} - {reason}")
        
        return result
    
    def terminate_process(self, process_id, reason):
        """Terminate a suspicious process (simulated)"""
        action_type = 'process_terminate'
        
        if self.simulation_mode:
            result = {
                'success': True,
                'action': 'simulated_process_terminate',
                'process_id': process_id,
                'message': f'[SIMULATED] Process {process_id} would be terminated: {reason}'
            }
        else:
            # In production, would use psutil or similar to kill process
            result = {
                'success': True,
                'action': 'process_terminate',
                'process_id': process_id,
                'message': f'Process {process_id} terminated'
            }
        
        remediation = RemediationAction(
            action_type=action_type,
            target=str(process_id),
            status='completed',
            details=reason,
            simulation_mode=self.simulation_mode
        )
        db.session.add(remediation)
        db.session.commit()
        
        log_to_database('WARNING', 'AutoRemediation', 
                       f"Process terminated: {process_id} - {reason}")
        
        return result
    
    def apply_remediation(self, threat):
        """Apply appropriate remediation based on threat type"""
        threat_type = threat.get('type', '')
        severity = threat.get('severity', 'Low')
        source_ip = threat.get('source_ip', '')
        
        actions_taken = []
        
        # High severity threats get automatic remediation
        if severity in ['High', 'Critical']:
            if source_ip:
                result = self.block_ip(source_ip, f"Auto-blocked due to {threat_type} threat", 
                                     duration_minutes=60 if severity == 'Medium' else 1440)
                actions_taken.append(result)
            
            # For critical threats, also lock associated accounts
            if severity == 'Critical' and 'username' in threat:
                result = self.lock_account(threat['username'], 
                                        f"Auto-locked due to critical {threat_type} threat")
                actions_taken.append(result)
        
        # Log the remediation action
        log_to_database('INFO', 'AutoRemediation', 
                       f"Applied remediation for {threat_type} threat from {source_ip}")
        
        return actions_taken
    
    def get_blocked_ips(self):
        """Get list of currently blocked IPs"""
        blocked = BlockedIP.query.filter_by(is_active=True).all()
        return [{
            'ip': b.ip_address,
            'reason': b.reason,
            'blocked_at': b.timestamp.isoformat(),
            'blocked_until': b.blocked_until.isoformat() if b.blocked_until else None
        } for b in blocked]
    
    def get_remediation_history(self, limit=50):
        """Get recent remediation actions"""
        actions = RemediationAction.query.order_by(
            RemediationAction.timestamp.desc()
        ).limit(limit).all()
        
        return [{
            'id': a.id,
            'timestamp': a.timestamp.isoformat(),
            'action_type': a.action_type,
            'target': a.target,
            'status': a.status,
            'details': a.details,
            'simulation_mode': a.simulation_mode
        } for a in actions]
    
    def set_simulation_mode(self, mode):
        """Toggle simulation mode"""
        self.simulation_mode = mode
        log_to_database('INFO', 'AutoRemediation', 
                       f"Simulation mode set to: {mode}")

# Singleton instance
_remediation = None

def get_remediation():
    global _remediation
    if _remediation is None:
        _remediation = AutoRemediation()
    return _remediation
