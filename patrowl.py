#!/usr/bin/env python
# encoding: utf-8
import requests, json
from cortexutils.analyzer import Analyzer

class PatrowlAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.getParam('config.service', None, 'Patrowl service is missing')
        self.url = self.getParam('config.url', None, 'Patrowl URL is missing').rstrip("/")
        self.username = self.getParam('config.username', None, 'Patrowl Username is missing')
        self.password = self.getParam('config.password', None, 'Patrowl Password is missing')

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "Patrowl"

        # getreport service
        if self.service == 'getreport':
            if 'risk_level' in raw and raw['risk_level']:

                # Grade
                if raw['risk_level']['grade'] in ["A", "B"]: level = "safe"
                else: level = "suspicious"
                taxonomies.append(self.build_taxonomy(
                    level, namespace, "Grade", raw['risk_level']['grade']))

                # Findings
                if raw['risk_level']['high'] > 0: level = "malicious"
                elif raw['risk_level']['medium'] > 0 or raw['risk_level']['low'] > 0: level = "suspicious"
                else: level = "info"
                taxonomies.append(self.build_taxonomy(
                    level, namespace, "Findings", "{}/{}/{}/{}".format(
                        raw['risk_level']['high'],
                        raw['risk_level']['medium'],
                        raw['risk_level']['low'],
                        raw['risk_level']['info']
                    )))
        #todo: add_asset service

        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)
        data = self.getData()

        try:
            if self.service == 'getreport':
                service_url = self.url+"/assets/api/v1/details/"+data
                response = requests.get(service_url, auth=requests.auth.HTTPBasicAuth(self.username, self.password))

                self.report(response.json())

            else:
                self.error('Unknown Patrowl service')

        except Exception as e:
            self.unexpectedError(e)

if __name__ == '__main__':
    PatrowlAnalyzer().run()
