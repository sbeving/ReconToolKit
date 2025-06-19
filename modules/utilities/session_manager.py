"""
Session Manager Module
Manages reconnaissance sessions, automation, and workflow orchestration.
"""

import logging
import json
import time
import uuid
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
from modules.base_module import BaseModule
import threading
import queue


class SessionState(Enum):
    """Session states."""
    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskStatus(Enum):
    """Task execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class SessionTask:
    """Represents a task within a session."""
    id: str
    module_name: str
    inputs: Dict[str, Any]
    config: Dict[str, Any]
    dependencies: List[str]
    status: TaskStatus
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    results: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3


@dataclass
class ReconSession:
    """Represents a reconnaissance session."""
    id: str
    name: str
    description: str
    target: str
    state: SessionState
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    tasks: List[SessionTask] = None
    results: Dict[str, Any] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.tasks is None:
            self.tasks = []
        if self.results is None:
            self.results = {}
        if self.metadata is None:
            self.metadata = {}


class SessionManagerModule(BaseModule):
    """Advanced session management and workflow orchestration."""
    
    def __init__(self):
        super().__init__(
            name="Session Manager",
            description="Manage reconnaissance sessions, automation workflows, and task orchestration",
            category="utilities"
        )
        
        self.logger = logging.getLogger(__name__)
        self.sessions: Dict[str, ReconSession] = {}
        self.active_sessions: Dict[str, threading.Thread] = {}
        self.task_queue = queue.Queue()
        self.session_callbacks: Dict[str, List[Callable]] = {}
        
        # Available modules for session tasks
        self.available_modules = {
            'domain_enumeration': 'modules.passive.domain_enumeration.DomainEnumerationModule',
            'email_intelligence': 'modules.passive.email_intelligence.EmailIntelligenceModule',
            'port_scanner': 'modules.active.port_scanner.PortScannerModule',
            'web_directory_enum': 'modules.active.web_directory_enum.WebDirectoryEnumerationModule',
            'web_fuzzer': 'modules.active.web_fuzzer.WebFuzzerModule',
            'vulnerability_scanner': 'modules.active.vulnerability_scanner.VulnerabilityScanner',
            'ssl_tls_analyzer': 'modules.active.ssl_tls_analyzer.SSLTLSAnalyzer',
            'network_discovery': 'modules.active.network_discovery.NetworkDiscoveryModule'
        }
        
        # Predefined workflows
        self.workflow_templates = {
            'comprehensive_web_audit': {
                'name': 'Comprehensive Web Application Audit',
                'description': 'Complete web application security assessment',
                'tasks': [
                    {'module': 'domain_enumeration', 'phase': 1},
                    {'module': 'port_scanner', 'phase': 2},
                    {'module': 'web_directory_enum', 'phase': 3},
                    {'module': 'vulnerability_scanner', 'phase': 4},
                    {'module': 'ssl_tls_analyzer', 'phase': 4},
                    {'module': 'web_fuzzer', 'phase': 5}
                ]
            },
            'network_reconnaissance': {
                'name': 'Network Reconnaissance',
                'description': 'Comprehensive network discovery and analysis',
                'tasks': [
                    {'module': 'network_discovery', 'phase': 1},
                    {'module': 'port_scanner', 'phase': 2},
                    {'module': 'vulnerability_scanner', 'phase': 3}
                ]
            },
            'osint_investigation': {
                'name': 'OSINT Investigation',
                'description': 'Open source intelligence gathering',
                'tasks': [
                    {'module': 'domain_enumeration', 'phase': 1},
                    {'module': 'email_intelligence', 'phase': 2}
                ]
            }
        }
    
    def get_input_fields(self) -> List[Dict[str, Any]]:
        return [
            {
                'name': 'operation',
                'type': 'combo',
                'label': 'Operation',
                'required': True,
                'default': 'create_session',
                'options': [
                    'create_session', 'list_sessions', 'get_session', 'start_session',
                    'pause_session', 'resume_session', 'cancel_session', 'delete_session',
                    'create_workflow', 'list_workflows', 'execute_workflow'
                ],
                'tooltip': 'Session management operation to perform'
            },
            {
                'name': 'session_id',
                'type': 'text',
                'label': 'Session ID',
                'required': False,
                'default': '',
                'placeholder': 'Session ID (for operations on existing sessions)'
            },
            {
                'name': 'session_name',
                'type': 'text',
                'label': 'Session Name',
                'required': False,
                'default': '',
                'placeholder': 'Name for new session'
            },
            {
                'name': 'session_description',
                'type': 'text',
                'label': 'Session Description',
                'required': False,
                'default': '',
                'placeholder': 'Description of the reconnaissance session'
            },
            {
                'name': 'target',
                'type': 'text',
                'label': 'Primary Target',
                'required': False,
                'default': '',
                'placeholder': 'Primary target for reconnaissance'
            },
            {
                'name': 'workflow_template',
                'type': 'combo',
                'label': 'Workflow Template',
                'required': False,
                'default': 'custom',
                'options': ['custom'] + list(self.workflow_templates.keys()),
                'tooltip': 'Predefined workflow template to use'
            },
            {
                'name': 'workflow_config',
                'type': 'file',
                'label': 'Workflow Configuration',
                'required': False,
                'default': '',
                'tooltip': 'JSON file containing workflow configuration'
            },
            {
                'name': 'auto_execute',
                'type': 'checkbox',
                'label': 'Auto Execute',
                'required': False,
                'default': False,
                'tooltip': 'Automatically start execution after session creation'
            },
            {
                'name': 'parallel_execution',
                'type': 'checkbox',
                'label': 'Parallel Execution',
                'required': False,
                'default': True,
                'tooltip': 'Allow parallel execution of independent tasks'
            },
            {
                'name': 'retry_failed_tasks',
                'type': 'checkbox',
                'label': 'Retry Failed Tasks',
                'required': False,
                'default': True,
                'tooltip': 'Automatically retry failed tasks'
            },
            {
                'name': 'max_concurrent_tasks',
                'type': 'number',
                'label': 'Max Concurrent Tasks',
                'required': False,
                'default': 3,
                'min': 1,
                'max': 10,
                'tooltip': 'Maximum number of concurrent tasks'
            }
        ]
    
    def validate_inputs(self, inputs: Dict[str, Any]) -> Optional[str]:
        operation = inputs.get('operation', '')
        if not operation:
            return "Operation is required"
        
        if operation in ['get_session', 'start_session', 'pause_session', 'resume_session', 'cancel_session', 'delete_session']:
            session_id = inputs.get('session_id', '').strip()
            if not session_id:
                return f"Session ID is required for {operation}"
            
            if operation != 'get_session' and session_id not in self.sessions:
                return f"Session '{session_id}' not found"
        
        if operation in ['create_session', 'create_workflow']:
            target = inputs.get('target', '').strip()
            if not target:
                return "Target is required for session/workflow creation"
        
        return None
    
    def run_scan(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute session management operation."""
        try:
            operation = inputs.get('operation', '')
            self.update_progress(f"Executing {operation}...", 10)
            
            if operation == 'create_session':
                return self._create_session(inputs, config)
            elif operation == 'list_sessions':
                return self._list_sessions()
            elif operation == 'get_session':
                return self._get_session(inputs.get('session_id'))
            elif operation == 'start_session':
                return self._start_session(inputs, config)
            elif operation == 'pause_session':
                return self._pause_session(inputs.get('session_id'))
            elif operation == 'resume_session':
                return self._resume_session(inputs.get('session_id'))
            elif operation == 'cancel_session':
                return self._cancel_session(inputs.get('session_id'))
            elif operation == 'delete_session':
                return self._delete_session(inputs.get('session_id'))
            elif operation == 'create_workflow':
                return self._create_workflow(inputs, config)
            elif operation == 'list_workflows':
                return self._list_workflows()
            elif operation == 'execute_workflow':
                return self._execute_workflow(inputs, config)
            else:
                return {
                    'success': False,
                    'error': f"Unknown operation: {operation}"
                }
        
        except Exception as e:
            self.logger.error(f"Error in session management: {e}")
            return {
                'success': False,
                'error': str(e),
                'operation': operation
            }
    
    def _create_session(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new reconnaissance session."""
        session_id = str(uuid.uuid4())
        session_name = inputs.get('session_name', f"Session_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        session_description = inputs.get('session_description', '')
        target = inputs.get('target', '')
        
        session = ReconSession(
            id=session_id,
            name=session_name,
            description=session_description,
            target=target,
            state=SessionState.CREATED,
            created_at=datetime.now().isoformat()
        )
        
        # Add workflow tasks if specified
        workflow_template = inputs.get('workflow_template', 'custom')
        workflow_config_file = inputs.get('workflow_config', '')
        
        if workflow_template != 'custom' and workflow_template in self.workflow_templates:
            tasks = self._create_tasks_from_template(workflow_template, target, config)
            session.tasks = tasks
        elif workflow_config_file:
            tasks = self._create_tasks_from_config(workflow_config_file, target, config)
            session.tasks = tasks
        
        self.sessions[session_id] = session
        
        # Auto-execute if requested
        auto_execute = inputs.get('auto_execute', False)
        if auto_execute and session.tasks:
            self._start_session_execution(session_id, config)
        
        self.update_progress("Session created successfully", 100)
        
        return {
            'success': True,
            'operation': 'create_session',
            'session_id': session_id,
            'session': asdict(session),
            'auto_executed': auto_execute
        }
    
    def _list_sessions(self) -> Dict[str, Any]:
        """List all sessions."""
        sessions_list = []
        
        for session_id, session in self.sessions.items():
            session_info = {
                'id': session.id,
                'name': session.name,
                'target': session.target,
                'state': session.state.value,
                'created_at': session.created_at,
                'task_count': len(session.tasks),
                'completed_tasks': len([t for t in session.tasks if t.status == TaskStatus.COMPLETED]),
                'is_active': session_id in self.active_sessions
            }
            sessions_list.append(session_info)
        
        return {
            'success': True,
            'operation': 'list_sessions',
            'sessions': sessions_list,
            'total_sessions': len(sessions_list),
            'active_sessions': len(self.active_sessions)
        }
    
    def _get_session(self, session_id: str) -> Dict[str, Any]:
        """Get detailed session information."""
        if session_id not in self.sessions:
            return {
                'success': False,
                'error': f"Session '{session_id}' not found"
            }
        
        session = self.sessions[session_id]
        
        return {
            'success': True,
            'operation': 'get_session',
            'session': asdict(session),
            'is_active': session_id in self.active_sessions
        }
    
    def _start_session(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Start session execution."""
        session_id = inputs.get('session_id')
        
        if session_id not in self.sessions:
            return {
                'success': False,
                'error': f"Session '{session_id}' not found"
            }
        
        session = self.sessions[session_id]
        
        if session.state not in [SessionState.CREATED, SessionState.PAUSED]:
            return {
                'success': False,
                'error': f"Cannot start session in state: {session.state.value}"
            }
        
        # Start session execution
        result = self._start_session_execution(session_id, config)
        
        return {
            'success': True,
            'operation': 'start_session',
            'session_id': session_id,
            'execution_started': result
        }
    
    def _start_session_execution(self, session_id: str, config: Dict[str, Any]) -> bool:
        """Start executing session tasks."""
        try:
            session = self.sessions[session_id]
            session.state = SessionState.RUNNING
            session.started_at = datetime.now().isoformat()
            
            # Create execution thread
            execution_thread = threading.Thread(
                target=self._execute_session_tasks,
                args=(session_id, config),
                daemon=True
            )
            
            self.active_sessions[session_id] = execution_thread
            execution_thread.start()
            
            return True
        
        except Exception as e:
            self.logger.error(f"Error starting session execution: {e}")
            return False
    
    def _execute_session_tasks(self, session_id: str, config: Dict[str, Any]):
        """Execute all tasks in a session."""
        try:
            session = self.sessions[session_id]
            parallel_execution = config.get('parallel_execution', True)
            max_concurrent = config.get('max_concurrent_tasks', 3)
            
            if parallel_execution:
                self._execute_tasks_parallel(session, max_concurrent)
            else:
                self._execute_tasks_sequential(session)
            
            # Update session state
            failed_tasks = [t for t in session.tasks if t.status == TaskStatus.FAILED]
            if failed_tasks:
                session.state = SessionState.FAILED
            else:
                session.state = SessionState.COMPLETED
            
            session.completed_at = datetime.now().isoformat()
            
            # Remove from active sessions
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]
        
        except Exception as e:
            self.logger.error(f"Error executing session tasks: {e}")
            session = self.sessions[session_id]
            session.state = SessionState.FAILED
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]
    
    def _execute_tasks_sequential(self, session: ReconSession):
        """Execute tasks sequentially."""
        for task in session.tasks:
            if session.state != SessionState.RUNNING:
                break
            
            self._execute_task(task, session)
    
    def _execute_tasks_parallel(self, session: ReconSession, max_concurrent: int):
        """Execute tasks in parallel based on dependencies."""
        remaining_tasks = session.tasks.copy()
        running_tasks = {}
        completed_tasks = set()
        
        while remaining_tasks or running_tasks:
            if session.state != SessionState.RUNNING:
                break
            
            # Start new tasks if we have capacity and ready tasks
            while len(running_tasks) < max_concurrent and remaining_tasks:
                # Find tasks that are ready to run (dependencies met)
                ready_tasks = [
                    task for task in remaining_tasks 
                    if all(dep in completed_tasks for dep in task.dependencies)
                ]
                
                if not ready_tasks:
                    break
                
                task = ready_tasks[0]
                remaining_tasks.remove(task)
                
                # Start task in thread
                task_thread = threading.Thread(
                    target=self._execute_task,
                    args=(task, session),
                    daemon=True
                )
                
                running_tasks[task.id] = task_thread
                task_thread.start()
            
            # Check for completed tasks
            completed_task_ids = []
            for task_id, thread in running_tasks.items():
                if not thread.is_alive():
                    completed_task_ids.append(task_id)
                    completed_tasks.add(task_id)
            
            # Remove completed tasks
            for task_id in completed_task_ids:
                del running_tasks[task_id]
            
            # Short sleep to avoid busy waiting
            time.sleep(0.5)
    
    def _execute_task(self, task: SessionTask, session: ReconSession):
        """Execute a single task."""
        try:
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.now().isoformat()
            
            # Get module instance
            module = self._get_module_instance(task.module_name)
            if not module:
                raise Exception(f"Module '{task.module_name}' not available")
            
            # Execute module
            results = module.run_scan(task.inputs, task.config)
            
            task.results = results
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.now().isoformat()
            
            # Store results in session
            session.results[task.id] = results
            
        except Exception as e:
            self.logger.error(f"Error executing task {task.id}: {e}")
            task.error = str(e)
            task.status = TaskStatus.FAILED
            task.completed_at = datetime.now().isoformat()
            
            # Retry if configured
            if task.retry_count < task.max_retries:
                task.retry_count += 1
                task.status = TaskStatus.PENDING
                # Could implement retry logic here
    
    def _get_module_instance(self, module_name: str):
        """Get instance of a reconnaissance module."""
        # This would need to be implemented to actually instantiate modules
        # For now, return None to indicate module not available
        return None
    
    def _create_tasks_from_template(self, template_name: str, target: str, config: Dict[str, Any]) -> List[SessionTask]:
        """Create tasks from a workflow template."""
        tasks = []
        template = self.workflow_templates[template_name]
        
        for i, task_def in enumerate(template['tasks']):
            task = SessionTask(
                id=str(uuid.uuid4()),
                module_name=task_def['module'],
                inputs={'target': target},  # Basic inputs, could be more sophisticated
                config=config,
                dependencies=[],  # Could implement phase-based dependencies
                status=TaskStatus.PENDING,
                created_at=datetime.now().isoformat()
            )
            tasks.append(task)
        
        return tasks
    
    def _create_tasks_from_config(self, config_file: str, target: str, config: Dict[str, Any]) -> List[SessionTask]:
        """Create tasks from configuration file."""
        tasks = []
        
        try:
            with open(config_file, 'r') as f:
                workflow_config = json.load(f)
            
            for task_config in workflow_config.get('tasks', []):
                task = SessionTask(
                    id=str(uuid.uuid4()),
                    module_name=task_config.get('module', ''),
                    inputs=task_config.get('inputs', {'target': target}),
                    config=task_config.get('config', config),
                    dependencies=task_config.get('dependencies', []),
                    status=TaskStatus.PENDING,
                    created_at=datetime.now().isoformat(),
                    max_retries=task_config.get('max_retries', 3)
                )
                tasks.append(task)
        
        except Exception as e:
            self.logger.error(f"Error loading workflow configuration: {e}")
        
        return tasks
    
    def _pause_session(self, session_id: str) -> Dict[str, Any]:
        """Pause session execution."""
        if session_id not in self.sessions:
            return {
                'success': False,
                'error': f"Session '{session_id}' not found"
            }
        
        session = self.sessions[session_id]
        session.state = SessionState.PAUSED
        
        return {
            'success': True,
            'operation': 'pause_session',
            'session_id': session_id
        }
    
    def _resume_session(self, session_id: str) -> Dict[str, Any]:
        """Resume session execution."""
        if session_id not in self.sessions:
            return {
                'success': False,
                'error': f"Session '{session_id}' not found"
            }
        
        session = self.sessions[session_id]
        if session.state != SessionState.PAUSED:
            return {
                'success': False,
                'error': f"Cannot resume session in state: {session.state.value}"
            }
        
        session.state = SessionState.RUNNING
        
        return {
            'success': True,
            'operation': 'resume_session',
            'session_id': session_id
        }
    
    def _cancel_session(self, session_id: str) -> Dict[str, Any]:
        """Cancel session execution."""
        if session_id not in self.sessions:
            return {
                'success': False,
                'error': f"Session '{session_id}' not found"
            }
        
        session = self.sessions[session_id]
        session.state = SessionState.CANCELLED
        
        # Stop active execution
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
        
        return {
            'success': True,
            'operation': 'cancel_session',
            'session_id': session_id
        }
    
    def _delete_session(self, session_id: str) -> Dict[str, Any]:
        """Delete a session."""
        if session_id not in self.sessions:
            return {
                'success': False,
                'error': f"Session '{session_id}' not found"
            }
        
        # Cancel if running
        if session_id in self.active_sessions:
            self._cancel_session(session_id)
        
        # Delete session
        del self.sessions[session_id]
        
        return {
            'success': True,
            'operation': 'delete_session',
            'session_id': session_id
        }
    
    def _create_workflow(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a workflow from inputs."""
        # This would create a new workflow template
        return {
            'success': True,
            'operation': 'create_workflow',
            'message': 'Workflow creation not yet implemented'
        }
    
    def _list_workflows(self) -> Dict[str, Any]:
        """List available workflow templates."""
        workflows = []
        
        for template_name, template in self.workflow_templates.items():
            workflow_info = {
                'name': template_name,
                'display_name': template['name'],
                'description': template['description'],
                'task_count': len(template['tasks']),
                'modules': list(set(task['module'] for task in template['tasks']))
            }
            workflows.append(workflow_info)
        
        return {
            'success': True,
            'operation': 'list_workflows',
            'workflows': workflows,
            'total_workflows': len(workflows)
        }
    
    def _execute_workflow(self, inputs: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a workflow directly."""
        # Create session and auto-execute
        inputs['auto_execute'] = True
        return self._create_session(inputs, config)
