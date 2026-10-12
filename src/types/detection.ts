import { SeverityLevel } from './event';

export interface DetectionAlert {
  id: string;
  caseId: string;
  ruleId: string;
  ruleName: string;
  severity: SeverityLevel;
  mitreTechnique: string;
  mitreTactic: string;
  timestamp: string;
  description: string;
  matchedEventIds: string[];
  falsePositive: boolean;
  falsePositiveReason?: string;
  falsePositiveMarkedBy?: string;
  entitiesInvolved: {
    hosts?: string[];
    users?: string[];
    ips?: string[];
  };
}

export interface SigmaRule {
  id: string;
  title: string;
  status: string;
  description: string;
  tags: string[];
  level: SeverityLevel;
  yamlContent: string;
}
