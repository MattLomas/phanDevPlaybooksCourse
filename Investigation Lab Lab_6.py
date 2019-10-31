"""
Investigation Lab from Lab 5 task 3
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'geolocate_ip_1' block
    geolocate_ip_1(container=container)

    # call 'file_reputation_1' block
    file_reputation_1(container=container)

    # call 'domain_reputation_1' block
    domain_reputation_1(container=container)

    return

"""
these were added - for task 2, then removed or reverted to allow for the UI screens to work.

phantom.debug("====Parameter list======")
phantom.debug(parameters)
phantom.debug("========================")
"""
def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('geolocate_ip_1() called')

    # collect data for 'geolocate_ip_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'geolocate_ip_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=join_filter_3, name="geolocate_ip_1")

    return

def domain_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('domain_reputation_1() called')

    # collect data for 'domain_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'domain_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("domain reputation", parameters=parameters, assets=['virustotal'], callback=join_filter_3, name="domain_reputation_1")

    return

def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('file_reputation_1() called')

    # collect data for 'file_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHash', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("file reputation", parameters=parameters, assets=['virustotal'], callback=decision_3, name="file_reputation_1")

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.summary.positives", ">=", 10],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        filter_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    apiAddComment(action=action, success=success, container=container, results=results, handle=handle)

    return

"""
Prompt block for Admin user to y/n a notification to IT Team.
"""
def Notify_IT_Team(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Notify_IT_Team() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """A potentially malicious file download has been detected on a local server with IP
address {0}. 
Notify IT team?"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:artifact:*.cef.destinationAddress",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="Notify_IT_Team", parameters=parameters, response_types=response_types, callback=decidePromoteToCaseCall)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Notify_IT_Team(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def decidePromoteToCaseCall(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decidePromoteToCaseCall() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Notify_IT_Team:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        Store_Country_Name(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    apiPINCardCloseContainer(action=action, success=success, container=container, results=results, handle=handle)

    return

def playbook_Matts_Repo_Case_Promotion_Lab_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('playbook_Matts_Repo_Case_Promotion_Lab_1() called')
    
    # call playbook "Matts Repo/Case Promotion Lab", returns the playbook_run_id
    playbook_run_id = phantom.playbook("Matts Repo/Case Promotion Lab", container=container)

    return

def apiAddComment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('apiAddComment() called')

    phantom.comment(container=container, comment="Threat level found to be low")
    apiPinHUDCard(container=container)

    return

def apiPinHUDCard(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('apiPinHUDCard() called')

    phantom.pin(container=container, data="", message="Processed and found harmless", pin_type="card", pin_style="blue", name="pbookPIN")
    apiSetStatusOfContainer(container=container)

    return

def apiSetStatusOfContainer(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('apiSetStatusOfContainer() called')

    phantom.set_status(container=container, status="Closed")

    return

def apiPINCardCloseContainer(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('apiPINCardCloseContainer() called')

    phantom.set_status(container=container, status="Closed")

    phantom.pin(container=container, data="", message="IT Team decision of NO so HUD Card Pinned and container status set to CLOSED.", pin_type="card", pin_style="blue", name=None)

    return

def apiCheckBannedCountryList(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('apiCheckBannedCountryList() called')

    inputs_data_1 = phantom.collect2(container=container, datapath=['file_reputation_1:artifact:*.cef.fileHash'], action_results=results)

    inputs_item_1_0 = [item[0] for item in inputs_data_1]

    phantom.add_list("Prior Hashes", inputs_item_1_0)
    join_filter_3(container=container)

    return

def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["custom_list:Banned Countries", "==", "geolocate_ip_1:action_result.data.*.country_name"],
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        decision_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["custom_list:Banned Countries", "!=", "geolocate_ip_1:action_result.data.*.country_name"],
        ],
        name="filter_3:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        apiAddHUDCardAndCloseContainer(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def join_filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_filter_3() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'domain_reputation_1', 'geolocate_ip_1', 'file_reputation_1' ]):
        
        # call connected block "filter_3"
        filter_3(container=container, handle=handle)
    
    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["", "!=", "custom_list:Prior Hashes"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        apiCheckBannedCountryList(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    join_filter_3(action=action, success=success, container=container, results=results, handle=handle)

    return

def apiAddHUDCardAndCloseContainer(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('apiAddHUDCardAndCloseContainer() called')

    results_data_1 = phantom.collect2(container=container, datapath=['geolocate_ip_1:action_result.data.*.country_name'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]

    phantom.pin(container=container, data=results_item_1_0, message="Country is safe and not on Banner Countries list", pin_type="card", pin_style="blue", name=None)

    phantom.set_status(container=container, status="Closed")

    return

def Store_Country_Name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Store_Country_Name() called')
    input_parameter_0 = ""

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################
    playbook_Matts_Repo_Case_Promotion_Lab_1(container=container)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions 
    # can be collected here.

    summary_json = phantom.get_summary()
    if 'result' in summary_json:
        for action_result in summary_json['result']:
             if 'action_run_id' in action_result:
                action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                phantom.debug(action_results)

    return