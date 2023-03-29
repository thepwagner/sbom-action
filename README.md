<p align="center">
  <a href="https://github.com/thepwagner/sbom-action/actions"><img alt="sbom-action status" src="https://github.com/thepwagner/sbom-action/workflows/build-test/badge.svg"></a>
</p>

# SBOM Action

GitHub Action with two behaviours related to SBOMs for container images.
Both expect an SBOM to be available on disk for an image that was just built (I suggest [aquasec/trivy-action](https://github.com/aquasecurity/trivy-action)).

When triggered from a pull request, the action will:
1. Fetch the SBOM associated with the `base-image` input (by default: the `:latest` tag in the GitHub container registry). 
2. Compare the `base-image` SBOM to a local SBOM.
3. Post a comment to the triggering pull request if there is any difference in detected packages or vulnerabilities.

When triggered from a schedule or workflow dispatch event, the action will:
1. Fetch the SBOM associated with the `base-image` input.
2. Compare the `base-image` SBOM to a local SBOM.
3. Open a new pull request if there is any difference in detected packages.

You can see this in use in: https://github.com/thepwagner-org/actions
