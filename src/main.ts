import * as core from '@actions/core'
import * as github from '@actions/github'
import type {WebhookEvent} from '@octokit/webhooks-types'
import {newHandler} from './action'

async function run(): Promise<void> {
  try {
    const handler = newHandler()

    const event = github.context.payload as WebhookEvent
    await handler.onEvent(github.context.eventName, event)
  } catch (error) {
    if (error instanceof Error) core.setFailed(error.message)
  }
}

run()
