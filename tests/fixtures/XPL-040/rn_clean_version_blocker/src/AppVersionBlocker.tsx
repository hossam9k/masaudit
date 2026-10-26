// A blocking screen for outdated versions, under its own name: it asks the backend whether to block.
import React from "react";
import { useAppVersionBlockCheck } from "./hooks/useAppVersionBlockCheck";

export const AppVersionBlocker = ({ children, appVersion }) => {
  const { shouldUpdate } = useAppVersionBlockCheck({ appVersion });
  return shouldUpdate ? <UpdateRequiredScreen /> : children;
};
